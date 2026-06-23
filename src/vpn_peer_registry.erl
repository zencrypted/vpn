%%%-------------------------------------------------------------------
%% @doc Runtime registry for provisioned VPN peers.
%%
%% Public reads expose only trusted metadata. Full runtime configuration is
%% available only through config/1 and enabled_configs/0 for the VPN runtime;
%% callers must never render those values in management responses.
%%%-------------------------------------------------------------------
-module(vpn_peer_registry).

-behaviour(gen_server).

-export([start_link/0,
         list/0,
         get/1,
         put/1,
         disable/1,
         enable/1,
         remove/1,
         config/1,
         enabled_configs/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(TABLE, vpn_peer_registry_entries).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

list() ->
    gen_server:call(?SERVER, list).

get(PeerId) ->
    gen_server:call(?SERVER, {get, PeerId}).

put(PeerConfig) ->
    gen_server:call(?SERVER, {put, PeerConfig}).

disable(PeerId) ->
    gen_server:call(?SERVER, {set_enabled, PeerId, false}).

enable(PeerId) ->
    gen_server:call(?SERVER, {set_enabled, PeerId, true}).

remove(PeerId) ->
    gen_server:call(?SERVER, {remove, PeerId}).

%% Internal runtime access. Never expose the returned configuration through
%% HTTP, JSON, logs, or administration status.
config(PeerId) ->
    gen_server:call(?SERVER, {config, PeerId}).

enabled_configs() ->
    gen_server:call(?SERVER, enabled_configs).

init([]) ->
    _ = ets:new(?TABLE, [named_table, set, protected, {read_concurrency, true}]),
    case vpn_session_config:configured_peers() of
        {ok, Peers} ->
            lists:foreach(
              fun(PeerConfig) ->
                      Entry = entry(PeerConfig, bootstrap_sys_config, true),
                      true = ets:insert(?TABLE, {maps:get(id, Entry), Entry})
              end,
              Peers),
            {ok, #{}};
        {error, Reason} ->
            {stop, {peer_registry_bootstrap_failed, Reason}}
    end.

handle_call(list, _From, State) ->
    Entries = [safe_entry(Entry) || {_PeerId, Entry} <- ets:tab2list(?TABLE)],
    {reply, lists:sort(fun compare_entries/2, Entries), State};
handle_call({get, PeerId}, _From, State) ->
    {reply, lookup_safe(PeerId), State};
handle_call({config, PeerId}, _From, State) ->
    Reply = case lookup(PeerId) of
                {ok, #{config := PeerConfig}} -> {ok, PeerConfig};
                {error, not_found} = Error -> Error
            end,
    {reply, Reply, State};
handle_call(enabled_configs, _From, State) ->
    Configs = [PeerConfig || {_PeerId, #{enabled := true, config := PeerConfig}}
                                 <- ets:tab2list(?TABLE)],
    {reply, lists:sort(fun compare_configs/2, Configs), State};
handle_call({put, PeerConfig}, _From, State) when is_map(PeerConfig) ->
    case maps:find(id, PeerConfig) of
        {ok, PeerId} when is_atom(PeerId); is_binary(PeerId) ->
            DefaultEnabled = existing_enabled(PeerId),
            Entry = entry(PeerConfig, runtime_api, DefaultEnabled),
            true = ets:insert(?TABLE, {PeerId, Entry}),
            {reply, {ok, safe_entry(Entry)}, State};
        _ ->
            {reply, {error, invalid_peer_config}, State}
    end;
handle_call({put, _PeerConfig}, _From, State) ->
    {reply, {error, invalid_peer_config}, State};
handle_call({set_enabled, PeerId, Enabled}, _From, State) ->
    case lookup(PeerId) of
        {ok, Entry} ->
            Updated = Entry#{enabled => Enabled},
            true = ets:insert(?TABLE, {PeerId, Updated}),
            {reply, {ok, safe_entry(Updated)}, State};
        {error, not_found} = Error ->
            {reply, Error, State}
    end;
handle_call({remove, PeerId}, _From, State) ->
    case lookup(PeerId) of
        {ok, _Entry} ->
            true = ets:delete(?TABLE, PeerId),
            {reply, ok, State};
        {error, not_found} = Error ->
            {reply, Error, State}
    end;
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_operation}, State}.

handle_cast(_Message, State) ->
    {noreply, State}.

handle_info(_Message, State) ->
    {noreply, State}.

lookup(PeerId) ->
    case ets:lookup(?TABLE, PeerId) of
        [{PeerId, Entry}] -> {ok, Entry};
        [] -> {error, not_found}
    end.

lookup_safe(PeerId) ->
    case lookup(PeerId) of
        {ok, Entry} -> {ok, safe_entry(Entry)};
        {error, not_found} = Error -> Error
    end.

existing_enabled(PeerId) ->
    case lookup(PeerId) of
        {ok, #{enabled := Enabled}} -> Enabled;
        {error, not_found} -> true
    end.

entry(PeerConfig, Source, DefaultEnabled) ->
    PeerId = maps:get(id, PeerConfig),
    Enabled = maps:get(enabled, PeerConfig, DefaultEnabled),
    Identity = maps:get(ovpn_identity, PeerConfig, #{}),
    #{id => PeerId,
      config => PeerConfig,
      enabled => Enabled,
      provisioning_source => maps:get(provisioning_source, PeerConfig, Source),
      device_id => maps:get(device_id, PeerConfig, undefined),
      authorization_mode => maps:get(authorization_mode, PeerConfig, policy),
      authorized => maps:get(authorized, PeerConfig, false),
      authorization_reason => maps:get(authorization_reason, PeerConfig, undefined),
      certificate_fingerprint => maps:get(certificate_fingerprint,
                                          Identity,
                                          maps:get(certificate_fingerprint,
                                                   PeerConfig,
                                                   undefined))}.

safe_entry(Entry) ->
    maps:with([id,
               enabled,
               provisioning_source,
               device_id,
               authorization_mode,
               authorized,
               authorization_reason,
               certificate_fingerprint],
              Entry).

compare_entries(#{id := A}, #{id := B}) ->
    A =< B.

compare_configs(#{id := A}, #{id := B}) ->
    A =< B.
