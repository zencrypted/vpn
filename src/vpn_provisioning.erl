%%%-------------------------------------------------------------------
%% @doc Revisioned IAS-to-VPN provisioning command contract.
%%
%% Commands are serialized by this process. Revisions are monotonic per peer,
%% duplicate delivery is idempotent, and removed peers retain an in-memory
%% tombstone so delayed commands cannot resurrect stale desired state.
%%%-------------------------------------------------------------------
-module(vpn_provisioning).
-behaviour(gen_server).

-export([start_link/0, apply/1, status/0, history/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(HISTORY_LIMIT, 50).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

apply(Command) ->
    gen_server:call(?SERVER, {apply, Command}, infinity).

status() ->
    gen_server:call(?SERVER, status).

history(PeerId) ->
    gen_server:call(?SERVER, {history, PeerId}).

init([]) ->
    {ok, #{heads => bootstrap_heads(),
           history => #{},
           commands_received => 0,
           commands_applied => 0,
           commands_unchanged => 0,
           commands_rejected => 0,
           stale_revisions => 0,
           revocations => 0,
           last_command => undefined,
           last_result => undefined}}.

handle_call(status, _From, State) ->
    {reply, maps:without([heads, history], State), State};
handle_call({history, PeerId}, _From, State) ->
    {reply, maps:get(PeerId, maps:get(history, State), []), State};
handle_call({apply, Command}, _From, State0) ->
    State1 = State0#{commands_received => maps:get(commands_received, State0) + 1},
    case validate_command(Command) of
        {ok, Normalized} ->
            {Reply, State2} = apply_validated(Normalized, State1),
            {reply, Reply, State2};
        {error, Reason} ->
            Result = {error, Reason},
            {reply, Result, record_rejected(Command, Result, State1)}
    end;
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_operation}, State}.

handle_cast(_Message, State) -> {noreply, State}.
handle_info(_Message, State) -> {noreply, State}.

apply_validated(Command = #{peer_id := PeerId, revision := Revision}, State) ->
    Heads = maps:get(heads, State),
    Head = maps:get(PeerId, Heads, #{revision => current_registry_revision(PeerId), digest => undefined}),
    CurrentRevision = maps:get(revision, Head),
    Digest = command_digest(Command),
    case Revision of
        R when R < CurrentRevision ->
            Result = {error, stale_revision},
            {Result, record_stale(Command, Result, State)};
        R when R =:= CurrentRevision ->
            case maps:get(digest, Head, undefined) of
                Digest ->
                    Result = {ok, unchanged},
                    {Result, record_unchanged(Command, Result, State)};
                _ ->
                    Result = {error, revision_conflict},
                    {Result, record_rejected(Command, Result, State)}
            end;
        _ ->
            case execute(Command) of
                {ok, Outcome} ->
                    NewHead = #{revision => Revision, digest => Digest},
                    State2 = State#{heads => Heads#{PeerId => NewHead}},
                    Result = {ok, Outcome},
                    {Result, record_applied(Command, Result, State2)};
                {error, Reason} ->
                    Result = {error, Reason},
                    {Result, record_rejected(Command, Result, State)}
            end
    end.

execute(#{operation := remove, peer_id := PeerId}) ->
    case vpn_peer_registry:remove(PeerId) of
        ok -> {ok, removed};
        {error, not_found} -> {ok, removed}
    end;
execute(Command = #{operation := Operation,
                    peer_id := PeerId,
                    revision := Revision,
                    source := Source}) ->
    Desired = maps:get(desired_state, Command, #{}),
    case base_config(PeerId, Desired) of
        {ok, BaseConfig} ->
            case next_config(Operation, BaseConfig, Desired) of
                {ok, Next0} ->
                    Now = erlang:system_time(second),
                    Next = Next0#{id => PeerId,
                                  revision => Revision,
                                  provisioning_source => Source,
                                  last_provisioning_operation => Operation,
                                  updated_at => Now},
                    persist_next_config(Operation, PeerId, BaseConfig, Next);
                Error -> Error
            end;
        Error -> Error
    end.

base_config(PeerId, Desired) ->
    case vpn_peer_registry:config(PeerId) of
        {ok, Config} -> {ok, Config};
        {error, not_found} ->
            case maps:get(runtime_config, Desired, undefined) of
                Runtime when is_map(Runtime) -> {ok, Runtime#{id => PeerId}};
                _ -> vpn_runtime_config_resolver:resolve(PeerId, Desired)
            end
    end.

next_config(upsert, Base, Desired) ->
    Runtime = maps:get(runtime_config, Desired, #{}),
    Public = maps:without([runtime_config], Desired),
    DesiredFields = maps:merge(Runtime, Public),
    RevokedBefore = maps:get(revoked, Base, false),
    Revoked = case maps:find(revoked, Public) of
                  {ok, false} -> false;
                  {ok, true} -> true;
                  error -> RevokedBefore
              end,
    Merged = (maps:merge(Base, DesiredFields))#{revoked => Revoked},
    {ok, normalize_authorization_metadata(Merged, DesiredFields)};
next_config(enable, Base, _Desired) ->
    case maps:get(revoked, Base, false) of
        true -> {error, revoked};
        false -> {ok, Base#{enabled => true}}
    end;
next_config(disable, Base, _Desired) ->
    {ok, Base#{enabled => false}};
next_config(revoke, Base, Desired) ->
    Public = maps:without([runtime_config], Desired),
    Reason = maps:get(authorization_reason, Public, revoked),
    {ok, (maps:merge(Base, Public))#{enabled => false,
                                   authorized => false,
                                   authorization_reason => Reason,
                                   revoked => true}}.

persist_next_config(disable, PeerId, BaseConfig, Next) ->
    case dynamic_gateway_config(PeerId, BaseConfig) of
        {ok, GatewayConfig} ->
            persist_dynamic_pair_disable(PeerId, GatewayConfig, Next);
        not_dynamic_client ->
            put_single_config(disable, Next);
        {error, Reason} ->
            logger:warning(
              "Dynamic client disable could not quiesce companion gateway: ~p",
              [Reason]),
            put_single_config(disable, Next)
    end;
persist_next_config(enable, PeerId, BaseConfig, Next) ->
    case dynamic_gateway_config(PeerId, BaseConfig) of
        {ok, GatewayConfig} ->
            persist_dynamic_pair_enable(PeerId,
                                        BaseConfig,
                                        GatewayConfig,
                                        Next);
        not_dynamic_client ->
            put_single_config(enable, Next);
        {error, Reason} ->
            {error, Reason}
    end;
persist_next_config(revoke, PeerId, BaseConfig, Next) ->
    case dynamic_gateway_config(PeerId, BaseConfig) of
        {ok, GatewayConfig} ->
            QuiescedGateway = GatewayConfig#{enabled => false},
            case vpn_peer_registry:put_many([QuiescedGateway, Next]) of
                {ok, SafeEntries} ->
                    case safe_peer_entry(PeerId, SafeEntries) of
                        {ok, Safe} ->
                            {ok, #{operation => revoke, peer => Safe}};
                        {error, _} = Error ->
                            Error
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        not_dynamic_client ->
            put_single_config(revoke, Next);
        {error, Reason} ->
            logger:warning(
              "Dynamic client revoke could not quiesce companion gateway: ~p",
              [Reason]),
            put_single_config(revoke, Next)
    end;
persist_next_config(Operation, _PeerId, _BaseConfig, Next) ->
    put_single_config(Operation, Next).

persist_dynamic_pair_disable(PeerId, GatewayConfig, Next) ->
    DeviceId = maps:get(device_id, Next),
    QuiescedGateway = GatewayConfig#{enabled => false},
    case vpn_peer_registry:put_many([QuiescedGateway, Next]) of
        {ok, SafeEntries} ->
            case vpn_dynamic_pair:await_stopped(DeviceId) of
                ok ->
                    pair_operation_result(disable, PeerId, SafeEntries);
                {error, _} = Error ->
                    Error
            end;
        {error, Reason} ->
            {error, Reason}
    end.

persist_dynamic_pair_enable(PeerId, BaseConfig, GatewayConfig, Next) ->
    DeviceId = maps:get(device_id, Next),
    EnabledGateway = GatewayConfig#{enabled => true},
    case vpn_peer_registry:put_many([EnabledGateway, Next]) of
        {ok, SafeEntries} ->
            case vpn_dynamic_pair:await_established(DeviceId) of
                ok ->
                    pair_operation_result(enable, PeerId, SafeEntries);
                {error, _} = Error ->
                    rollback_failed_pair_enable(DeviceId,
                                                BaseConfig,
                                                GatewayConfig),
                    Error
            end;
        {error, Reason} ->
            {error, Reason}
    end.

rollback_failed_pair_enable(DeviceId, BaseConfig, GatewayConfig) ->
    DisabledClient = BaseConfig#{enabled => false},
    DisabledGateway = GatewayConfig#{enabled => false},
    case vpn_peer_registry:put_many([DisabledGateway, DisabledClient]) of
        {ok, _} ->
            _ = vpn_dynamic_pair:await_stopped(DeviceId),
            ok;
        {error, Reason} ->
            logger:error("Dynamic pair enable rollback failed: ~p", [Reason]),
            ok
    end.

pair_operation_result(Operation, PeerId, SafeEntries) ->
    case safe_peer_entry(PeerId, SafeEntries) of
        {ok, Safe} ->
            {ok, #{operation => Operation, peer => Safe}};
        {error, _} = Error ->
            Error
    end.

put_single_config(Operation, Next) ->
    case vpn_peer_registry:put(Next) of
        {ok, Safe} -> {ok, #{operation => Operation, peer => Safe}};
        {error, Reason} -> {error, Reason}
    end.

dynamic_gateway_config(ClientId,
                       #{allocation_role := client,
                         allocation_id := AllocationId,
                         device_id := DeviceId,
                         remote_peer_id := GatewayId}) ->
    case vpn_peer_registry:config(GatewayId) of
        {ok, GatewayConfig} ->
            case maps:get(allocation_role, GatewayConfig, undefined) =:= gateway andalso
                 maps:get(allocation_id, GatewayConfig, undefined) =:= AllocationId andalso
                 maps:get(device_id, GatewayConfig, undefined) =:= DeviceId andalso
                 maps:get(remote_peer_id, GatewayConfig, undefined) =:= ClientId of
                true -> {ok, GatewayConfig};
                false -> {error, {dynamic_pair_gateway_mismatch, GatewayId}}
            end;
        {error, not_found} ->
            {error, {dynamic_pair_gateway_not_found, GatewayId}}
    end;
dynamic_gateway_config(_PeerId, _BaseConfig) ->
    not_dynamic_client.

safe_peer_entry(PeerId, SafeEntries) ->
    case [Entry || #{id := Id} = Entry <- SafeEntries, Id =:= PeerId] of
        [Safe] -> {ok, Safe};
        _ -> {error, dynamic_pair_client_result_missing}
    end.


normalize_authorization_metadata(Config, DesiredFields) ->
    AuthorizationChanged = maps:is_key(authorization_mode, DesiredFields) orelse
                           maps:is_key(authorized, DesiredFields),
    ReasonProvided = maps:is_key(authorization_reason, DesiredFields),
    case AuthorizationChanged andalso not ReasonProvided of
        true -> Config#{authorization_reason => undefined};
        false -> Config
    end.

validate_command(Command) when is_map(Command) ->
    PeerId = maps:get(peer_id, Command, undefined),
    Revision = maps:get(revision, Command, undefined),
    Operation = maps:get(operation, Command, undefined),
    Source = maps:get(source, Command, undefined),
    Desired = maps:get(desired_state, Command, #{}),
    case {valid_peer_id(PeerId), is_integer(Revision) andalso Revision >= 0,
          lists:member(Operation, [upsert, enable, disable, revoke, remove]),
          valid_source(Source), is_map(Desired)} of
        {true, true, true, true, true} ->
            {ok, #{peer_id => PeerId,
                   revision => Revision,
                   operation => Operation,
                   source => Source,
                   desired_state => Desired}};
        _ -> {error, invalid_command}
    end;
validate_command(_) ->
    {error, invalid_command}.

valid_peer_id(Value) -> is_atom(Value) orelse is_binary(Value).
valid_source(Value) -> is_atom(Value) orelse is_binary(Value).

current_registry_revision(PeerId) ->
    case vpn_peer_registry:get(PeerId) of
        {ok, Entry} -> maps:get(revision, Entry, 0);
        {error, not_found} -> 0
    end.

bootstrap_heads() ->
    maps:from_list([{maps:get(id, Entry),
                     #{revision => maps:get(revision, Entry, 0), digest => undefined}}
                    || Entry <- vpn_peer_registry:list()]).

command_digest(Command) ->
    crypto:hash(sha256, term_to_binary(Command, [deterministic])).

command_summary(Command) when is_map(Command) ->
    maps:with([peer_id, revision, operation, source], Command);
command_summary(_) -> undefined.

record_applied(Command, Result, State0) ->
    State1 = add_history(Command, Result, State0),
    Revocations = maps:get(revocations, State1) +
        case maps:get(operation, Command) of revoke -> 1; _ -> 0 end,
    State1#{commands_applied => maps:get(commands_applied, State1) + 1,
            revocations => Revocations,
            last_command => command_summary(Command),
            last_result => Result}.

record_unchanged(Command, Result, State0) ->
    State1 = add_history(Command, Result, State0),
    State1#{commands_unchanged => maps:get(commands_unchanged, State1) + 1,
            last_command => command_summary(Command), last_result => Result}.

record_stale(Command, Result, State0) ->
    State1 = add_history(Command, Result, State0),
    State1#{commands_rejected => maps:get(commands_rejected, State1) + 1,
            stale_revisions => maps:get(stale_revisions, State1) + 1,
            last_command => command_summary(Command), last_result => Result}.

record_rejected(Command, Result, State0) ->
    State = maybe_add_history(Command, Result, State0),
    State#{commands_rejected => maps:get(commands_rejected, State) + 1,
           last_command => command_summary(Command), last_result => Result}.

maybe_add_history(Command, Result, State) when is_map(Command) ->
    case maps:is_key(peer_id, Command) andalso
         maps:is_key(revision, Command) andalso
         maps:is_key(operation, Command) andalso
         maps:is_key(source, Command) of
        true -> add_history(Command, Result, State);
        false -> State
    end;
maybe_add_history(_Command, _Result, State) ->
    State.

add_history(Command, Result, State) ->
    PeerId = maps:get(peer_id, Command),
    Histories = maps:get(history, State),
    Existing = maps:get(PeerId, Histories, []),
    Entry = (command_summary(Command))#{result => Result,
                                      recorded_at => erlang:system_time(second)},
    Updated = lists:sublist([Entry | Existing], ?HISTORY_LIMIT),
    State#{history => Histories#{PeerId => Updated}}.
