%%%-------------------------------------------------------------------
%% @doc Serialized durable projection boundary.
%%
%% Stage 8A.1 deliberately does not connect allocator or provisioning state to
%% this process yet. It establishes the versioned, checksummed and replaceable
%% backend contract that later stages will consume.
%%%-------------------------------------------------------------------
-module(vpn_projection).

-behaviour(gen_server).

-export([start_link/0,
         get/0,
         update/2,
         replace/2,
         status/0]).
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).
-define(SCHEMA_VERSION, 1).

-record(state, {
    backend,
    version = 0,
    projection = #{allocator => #{}, provisioning => #{}},
    updated_at = 0
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

get() ->
    gen_server:call(?SERVER, get).

update(Section, Fun) when is_function(Fun, 1) ->
    gen_server:call(?SERVER, {update, Section, Fun}, infinity);
update(_Section, _Fun) ->
    {error, invalid_projection_update}.

replace(ExpectedVersion, Projection) ->
    gen_server:call(?SERVER,
                    {replace, ExpectedVersion, Projection},
                    infinity).

status() ->
    gen_server:call(?SERVER, status).

init([]) ->
    case configured_backend() of
        {ok, Backend} ->
            case load_projection(Backend) of
                {ok, Version, Projection, UpdatedAt} ->
                    {ok, #state{backend = Backend,
                                version = Version,
                                projection = Projection,
                                updated_at = UpdatedAt}};
                {error, Reason} ->
                    {stop, {projection_load_failed, Reason}}
            end;
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(get, _From, State) ->
    {reply, {ok, State#state.version, State#state.projection}, State};
handle_call(status, _From, State) ->
    {reply, #{state => ready,
              persistence => durable,
              backend => State#state.backend,
              schema_version => ?SCHEMA_VERSION,
              projection_version => State#state.version,
              updated_at => State#state.updated_at},
     State};
handle_call({update, Section, Fun}, _From, State) ->
    case allowed_section(Section) of
        false ->
            {reply, {error, {invalid_projection_section, Section}}, State};
        true ->
            CurrentSection = maps:get(Section, State#state.projection),
            case apply_update(Fun, CurrentSection) of
                {ok, NewSection} when is_map(NewSection) ->
                    NewProjection = maps:put(Section,
                                             NewSection,
                                             State#state.projection),
                    commit_projection(State#state.version,
                                      NewProjection,
                                      State);
                {ok, _Invalid} ->
                    {reply, {error, invalid_projection_section_value}, State};
                {error, Reason} ->
                    {reply, {error, Reason}, State}
            end
    end;
handle_call({replace, ExpectedVersion, Projection}, _From, State)
  when is_integer(ExpectedVersion), ExpectedVersion >= 0 ->
    case ExpectedVersion =:= State#state.version of
        true ->
            commit_projection(ExpectedVersion, Projection, State);
        false ->
            {reply, {error, conflict}, State}
    end;
handle_call({replace, _ExpectedVersion, _Projection}, _From, State) ->
    {reply, {error, invalid_expected_version}, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_projection_request}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

configured_backend() ->
    case application:get_env(vpn,
                             projection_store_backend,
                             vpn_projection_store_kvs) of
        Backend when is_atom(Backend) ->
            case code:ensure_loaded(Backend) of
                {module, Backend} -> {ok, Backend};
                {error, Reason} ->
                    {error, {projection_backend_unavailable,
                             Backend,
                             Reason}}
            end;
        Invalid ->
            {error, {invalid_projection_store_backend, Invalid}}
    end.

load_projection(Backend) ->
    case safe_backend_call(Backend, load, []) of
        not_found ->
            {ok, 0, initial_projection(), 0};
        {ok, Version, Envelope} ->
            validate_loaded_envelope(Version, Envelope);
        {error, Reason} ->
            {error, Reason};
        Other ->
            {error, {invalid_projection_load_result, Other}}
    end.

validate_loaded_envelope(Version,
                         #{schema_version := SchemaVersion,
                           projection_version := EnvelopeVersion,
                           checksum := Checksum,
                           payload := Projection,
                           updated_at := UpdatedAt}) ->
    case SchemaVersion of
        ?SCHEMA_VERSION ->
            validate_loaded_contents(Version,
                                     EnvelopeVersion,
                                     Projection,
                                     UpdatedAt,
                                     Checksum);
        _ ->
            {error, {unsupported_schema_version, SchemaVersion}}
    end;
validate_loaded_envelope(_Version, _Envelope) ->
    {error, invalid_projection_envelope}.

validate_loaded_contents(Version,
                         Version,
                         Projection,
                         UpdatedAt,
                         Checksum)
  when is_integer(Version), Version > 0,
       is_integer(UpdatedAt), UpdatedAt >= 0,
       is_binary(Checksum), byte_size(Checksum) =:= 32 ->
    case validate_projection(Projection) of
        ok ->
            ExpectedChecksum = projection_checksum(?SCHEMA_VERSION,
                                                   Version,
                                                   Projection,
                                                   UpdatedAt),
            case secure_equal(Checksum, ExpectedChecksum) of
                true -> {ok, Version, Projection, UpdatedAt};
                false -> {error, invalid_projection_checksum}
            end;
        {error, Reason} ->
            {error, Reason}
    end;
validate_loaded_contents(_Version,
                         _EnvelopeVersion,
                         _Projection,
                         _UpdatedAt,
                         _Checksum) ->
    {error, invalid_projection_envelope}.

commit_projection(ExpectedVersion, Projection, State) ->
    case validate_projection(Projection) of
        ok when Projection =:= State#state.projection ->
            {reply,
             {ok, unchanged, State#state.version, State#state.projection},
             State};
        ok ->
            NewVersion = ExpectedVersion + 1,
            UpdatedAt = erlang:system_time(millisecond),
            Envelope = build_envelope(NewVersion, Projection, UpdatedAt),
            Backend = State#state.backend,
            case safe_backend_call(Backend,
                                   commit,
                                   [ExpectedVersion, Envelope]) of
                {ok, NewVersion} ->
                    NewState = State#state{version = NewVersion,
                                           projection = Projection,
                                           updated_at = UpdatedAt},
                    {reply, {ok, NewVersion, Projection}, NewState};
                {error, conflict} ->
                    {reply, {error, conflict}, State};
                {error, Reason} ->
                    {reply, {error, {projection_commit_failed, Reason}}, State};
                Other ->
                    {reply,
                     {error, {invalid_projection_commit_result, Other}},
                     State}
            end;
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end.

build_envelope(Version, Projection, UpdatedAt) ->
    #{schema_version => ?SCHEMA_VERSION,
      projection_version => Version,
      checksum => projection_checksum(?SCHEMA_VERSION,
                                      Version,
                                      Projection,
                                      UpdatedAt),
      payload => Projection,
      updated_at => UpdatedAt}.

projection_checksum(SchemaVersion, Version, Projection, UpdatedAt) ->
    crypto:hash(sha256,
                term_to_binary({SchemaVersion,
                                Version,
                                Projection,
                                UpdatedAt})).

validate_projection(#{allocator := Allocator,
                      provisioning := Provisioning} = Projection)
  when is_map(Allocator), is_map(Provisioning), map_size(Projection) =:= 2 ->
    reject_forbidden_material(Projection);
validate_projection(_Projection) ->
    {error, invalid_projection_payload}.

reject_forbidden_material(Term) when is_map(Term) ->
    maps:fold(
      fun(Key, Value, ok) ->
              case forbidden_key(Key) of
                  true ->
                      {error, {forbidden_projection_key, Key}};
                  false ->
                      case reject_forbidden_material(Key) of
                          ok -> reject_forbidden_material(Value);
                          Error -> Error
                      end
              end;
         (_Key, _Value, Error) ->
              Error
      end,
      ok,
      Term);
reject_forbidden_material([Head | Tail]) ->
    case reject_forbidden_material(Head) of
        ok -> reject_forbidden_material(Tail);
        Error -> Error
    end;
reject_forbidden_material([]) ->
    ok;
reject_forbidden_material(Term) when is_tuple(Term) ->
    reject_forbidden_material(tuple_to_list(Term));
reject_forbidden_material(Term) when is_pid(Term) ->
    {error, {forbidden_projection_term, pid}};
reject_forbidden_material(Term) when is_port(Term) ->
    {error, {forbidden_projection_term, port}};
reject_forbidden_material(Term) when is_reference(Term) ->
    {error, {forbidden_projection_term, reference}};
reject_forbidden_material(Term) when is_function(Term) ->
    {error, {forbidden_projection_term, function}};
reject_forbidden_material(_Term) ->
    ok.

forbidden_key(Key) when is_atom(Key) ->
    forbidden_key_name(atom_to_list(Key));
forbidden_key(Key) when is_binary(Key) ->
    forbidden_key_name(binary_to_list(Key));
forbidden_key(Key) when is_list(Key) ->
    forbidden_key_name(Key);
forbidden_key(_Key) ->
    false.

forbidden_key_name(Name) ->
    lists:member(string:lowercase(Name),
                 [atom_to_list(Atom) || Atom <- forbidden_keys()]).

forbidden_keys() ->
    [psk,
     private_key,
     private_key_pem,
     private_key_path,
     session_key,
     session_keys,
     session_material,
     ecdh_private_key,
     handshake_secret,
     packet_key,
     replay_window,
     replay_windows,
     ovpn_contents].

allowed_section(allocator) -> true;
allowed_section(provisioning) -> true;
allowed_section(_) -> false.

apply_update(Fun, CurrentSection) ->
    try Fun(CurrentSection) of
        {ok, NewSection} -> {ok, NewSection};
        {error, Reason} -> {error, Reason};
        NewSection -> {ok, NewSection}
    catch
        Class:Reason:Stacktrace ->
            {error, {projection_update_failed,
                     Class,
                     Reason,
                     Stacktrace}}
    end.

safe_backend_call(Backend, Function, Arguments) ->
    try apply(Backend, Function, Arguments)
    catch
        Class:Reason:Stacktrace ->
            {error, {projection_backend_failure,
                     Backend,
                     Function,
                     Class,
                     Reason,
                     Stacktrace}}
    end.

secure_equal(Left, Right)
  when is_binary(Left), is_binary(Right), byte_size(Left) =:= byte_size(Right) ->
    secure_equal(Left, Right, 0) =:= 0;
secure_equal(_Left, _Right) ->
    false.

secure_equal(<<>>, <<>>, Acc) ->
    Acc;
secure_equal(<<Left, LeftRest/binary>>, <<Right, RightRest/binary>>, Acc) ->
    secure_equal(LeftRest, RightRest, Acc bor (Left bxor Right)).

initial_projection() ->
    #{allocator => #{}, provisioning => #{}}.
