%%%-------------------------------------------------------------------
%% @doc Runtime registry for provisioned VPN peers.
%%
%% Public reads expose only trusted metadata. During startup the registry first
%% loads trusted bootstrap peers and then reconstructs eligible durable runtime
%% entries before vpn_peer_sup starts. Full runtime configuration is available
%% only through config/1 and enabled_configs/0 for the VPN runtime; callers must
%% never render those values in management responses.
%%%-------------------------------------------------------------------
-module(vpn_peer_registry).

-behaviour(gen_server).

-export([start_link/0,
         list/0,
         get/1,
         put/1,
         put_many/1,
         disable/1,
         enable/1,
         remove/1,
         remove_many/1,
         remove_many_if_owned/3,
         config/1,
         enabled_configs/0,
         recovery_status/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(TABLE, vpn_peer_registry_entries).
-define(NON_RESTART_FIELDS,
        [revision,
         provisioning_source,
         last_provisioning_operation,
         updated_at]).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

list() ->
    gen_server:call(?SERVER, list).

get(PeerId) ->
    gen_server:call(?SERVER, {get, PeerId}).

put(PeerConfig) ->
    gen_server:call(?SERVER, {put, PeerConfig}).

put_many(PeerConfigs) ->
    gen_server:call(?SERVER, {put_many, PeerConfigs}).

disable(PeerId) ->
    gen_server:call(?SERVER, {set_enabled, PeerId, false}).

enable(PeerId) ->
    gen_server:call(?SERVER, {set_enabled, PeerId, true}).

remove(PeerId) ->
    gen_server:call(?SERVER, {remove, PeerId}).

remove_many(PeerIds) ->
    gen_server:call(?SERVER, {remove_many, PeerIds}).

%% @doc Idempotently remove only entries owned by the expected IAS Device.
%%
%% Missing entries are accepted for saga retry. Any present peer with a
%% different Device or provisioning source aborts the whole batch before a
%% mutation is made.
remove_many_if_owned(DeviceId, PeerIds, ias)
  when is_binary(DeviceId), byte_size(DeviceId) > 0,
       is_list(PeerIds), PeerIds =/= [] ->
    gen_server:call(?SERVER, {remove_many_if_owned, DeviceId, PeerIds, ias});
remove_many_if_owned(_DeviceId, _PeerIds, _Source) ->
    {error, invalid_owned_peer_removal_request}.

%% Internal runtime access. Never expose the returned configuration through
%% HTTP, JSON, logs, or administration status.
config(PeerId) ->
    gen_server:call(?SERVER, {config, PeerId}).

enabled_configs() ->
    gen_server:call(?SERVER, enabled_configs).

recovery_status() ->
    gen_server:call(?SERVER, recovery_status).

init([]) ->
    _ = ets:new(?TABLE, [named_table, set, protected, {read_concurrency, true}]),
    case vpn_session_config:configured_peers() of
        {ok, Peers} ->
            case vpn_runtime_recovery:restore(Peers) of
                {ok, RuntimePeers, RecoveryStatus} ->
                    lists:foreach(
                      fun(PeerConfig) ->
                              Enabled = maps:get(enabled, PeerConfig, true),
                              Entry = entry(PeerConfig,
                                            durable_recovery,
                                            Enabled),
                              true = ets:insert(
                                       ?TABLE,
                                       {maps:get(id, Entry), Entry})
                      end,
                      RuntimePeers),
                    {ok, #{recovery => RecoveryStatus}};
                {error, Reason} ->
                    {stop, {peer_registry_recovery_failed, Reason}}
            end;
        {error, Reason} ->
            {stop, {peer_registry_bootstrap_failed, Reason}}
    end.

handle_call(list, _From, State) ->
    Entries = [safe_entry(Entry) || {_PeerId, Entry} <- ets:tab2list(?TABLE)],
    {reply, lists:sort(fun compare_entries/2, Entries), State};
handle_call(recovery_status, _From, State) ->
    {reply, maps:get(recovery, State), State};
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
            Previous = lookup(PeerId),
            DefaultEnabled = existing_enabled(PeerId),
            Entry = entry(PeerConfig, runtime_api, DefaultEnabled),
            RestartRequired = restart_required(Previous, PeerConfig),
            true = ets:insert(?TABLE, {PeerId, Entry}),
            notify_reconciler(#{action => put,
                                peer_id => PeerId,
                                restart_required => RestartRequired}),
            {reply, {ok, safe_entry(Entry)}, State};
        _ ->
            {reply, {error, invalid_peer_config}, State}
    end;
handle_call({put, _PeerConfig}, _From, State) ->
    {reply, {error, invalid_peer_config}, State};
handle_call({put_many, PeerConfigs}, _From, State) ->
    case batch_entries(PeerConfigs) of
        {ok, Entries} ->
            PeerChanges = [#{peer_id => maps:get(id, Entry),
                             restart_required =>
                                 restart_required(lookup(maps:get(id, Entry)),
                                                  maps:get(config, Entry))}
                           || Entry <- Entries],
            true = ets:insert(?TABLE,
                              [{maps:get(id, Entry), Entry} || Entry <- Entries]),
            notify_reconciler(#{action => put_many,
                                peer_changes => PeerChanges}),
            {reply, {ok, [safe_entry(Entry) || Entry <- Entries]}, State};
        {error, _} = Error ->
            {reply, Error, State}
    end;
handle_call({set_enabled, PeerId, Enabled}, _From, State) ->
    case lookup(PeerId) of
        {ok, Entry} ->
            Updated = Entry#{enabled => Enabled},
            true = ets:insert(?TABLE, {PeerId, Updated}),
            notify_reconciler(#{action => set_enabled,
                                peer_id => PeerId,
                                enabled => Enabled}),
            {reply, {ok, safe_entry(Updated)}, State};
        {error, not_found} = Error ->
            {reply, Error, State}
    end;
handle_call({remove, PeerId}, _From, State) ->
    case lookup(PeerId) of
        {ok, _Entry} ->
            true = ets:delete(?TABLE, PeerId),
            notify_reconciler(#{action => remove, peer_id => PeerId}),
            {reply, ok, State};
        {error, not_found} = Error ->
            {reply, Error, State}
    end;
handle_call({remove_many, PeerIds}, _From, State) ->
    case valid_peer_ids(PeerIds) of
        true ->
            lists:foreach(fun(PeerId) -> true = ets:delete(?TABLE, PeerId) end,
                          PeerIds),
            notify_reconciler(#{action => remove_many, peer_ids => PeerIds}),
            {reply, ok, State};
        false ->
            {reply, {error, invalid_peer_ids}, State}
    end;
handle_call({remove_many_if_owned, DeviceId, PeerIds, ias}, _From, State) ->
    case valid_peer_ids(PeerIds) of
        false ->
            {reply, {error, invalid_peer_ids}, State};
        true ->
            case validate_owned_peer_removal(DeviceId, PeerIds) of
                ok ->
                    lists:foreach(
                      fun(PeerId) -> true = ets:delete(?TABLE, PeerId) end,
                      PeerIds),
                    notify_reconciler(#{action => remove_many,
                                        peer_ids => PeerIds}),
                    {reply, ok, State};
                {error, _} = Error ->
                    {reply, Error, State}
            end
    end;
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_operation}, State}.

handle_cast(_Message, State) ->
    {noreply, State}.

handle_info(_Message, State) ->
    {noreply, State}.

validate_owned_peer_removal(DeviceId, PeerIds) ->
    lists:foldl(
      fun(_PeerId, {error, _} = Error) -> Error;
         (PeerId, ok) ->
              case ets:lookup(?TABLE, PeerId) of
                  [] -> ok;
                  [{PeerId, Entry}] ->
                      case {maps:get(device_id, Entry, undefined),
                            maps:get(provisioning_source, Entry, undefined)} of
                          {DeviceId, ias} -> ok;
                          _ -> {error, {peer_ownership_conflict, PeerId}}
                      end
              end
      end,
      ok,
      PeerIds).

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

batch_entries(PeerConfigs) when is_list(PeerConfigs), PeerConfigs =/= [] ->
    case lists:all(fun valid_peer_config/1, PeerConfigs) of
        true ->
            PeerIds = [maps:get(id, PeerConfig) || PeerConfig <- PeerConfigs],
            case length(PeerIds) =:= length(lists:usort(PeerIds)) of
                true ->
                    {ok, [entry(PeerConfig,
                                runtime_api,
                                existing_enabled(maps:get(id, PeerConfig)))
                          || PeerConfig <- PeerConfigs]};
                false ->
                    {error, duplicate_peer_id}
            end;
        false ->
            {error, invalid_peer_config}
    end;
batch_entries(_PeerConfigs) ->
    {error, invalid_peer_config}.

valid_peer_config(PeerConfig) when is_map(PeerConfig) ->
    case maps:find(id, PeerConfig) of
        {ok, PeerId} -> valid_peer_id(PeerId);
        error -> false
    end;
valid_peer_config(_PeerConfig) ->
    false.

valid_peer_ids(PeerIds) when is_list(PeerIds) ->
    PeerIds =/= [] andalso
    lists:all(fun valid_peer_id/1, PeerIds) andalso
    length(PeerIds) =:= length(lists:usort(PeerIds));
valid_peer_ids(_PeerIds) ->
    false.

valid_peer_id(PeerId) ->
    is_atom(PeerId) orelse is_binary(PeerId).

entry(PeerConfig, Source, DefaultEnabled) ->
    PeerId = maps:get(id, PeerConfig),
    Enabled = maps:get(enabled, PeerConfig, DefaultEnabled),
    Identity = maps:get(ovpn_identity, PeerConfig, #{}),
    #{id => PeerId,
      config => PeerConfig,
      enabled => Enabled,
      provisioning_source => maps:get(provisioning_source, PeerConfig, Source),
      device_id => maps:get(device_id, PeerConfig, undefined),
      allocation_id => maps:get(allocation_id, PeerConfig, undefined),
      allocator_instance_id => maps:get(allocator_instance_id, PeerConfig, undefined),
      allocation_slot => maps:get(allocation_slot, PeerConfig, undefined),
      allocation_generation => maps:get(allocation_generation, PeerConfig, undefined),
      allocation_role => maps:get(allocation_role, PeerConfig, undefined),
      profile_id => maps:get(profile_id, PeerConfig, undefined),
      authorization_mode => maps:get(authorization_mode, PeerConfig, policy),
      authorized => maps:get(authorized, PeerConfig, false),
      authorization_reason => maps:get(authorization_reason, PeerConfig, undefined),
      certificate_fingerprint => maps:get(certificate_fingerprint,
                                          Identity,
                                          maps:get(certificate_fingerprint,
                                                   PeerConfig,
                                                   undefined)),
      revision => maps:get(revision, PeerConfig, 0),
      revoked => maps:get(revoked, PeerConfig, false),
      last_provisioning_operation => maps:get(last_provisioning_operation,
                                              PeerConfig,
                                              undefined),
      updated_at => maps:get(updated_at, PeerConfig, undefined)}.

safe_entry(Entry) ->
    maps:with([id,
               enabled,
               provisioning_source,
               device_id,
               allocation_id,
               allocator_instance_id,
               allocation_slot,
               allocation_generation,
               allocation_role,
               profile_id,
               authorization_mode,
               authorized,
               authorization_reason,
               certificate_fingerprint,
               revision,
               revoked,
               last_provisioning_operation,
               updated_at],
              Entry).

compare_entries(#{id := A}, #{id := B}) ->
    A =< B.

compare_configs(#{id := A}, #{id := B}) ->
    A =< B.

restart_required({error, not_found}, _NewConfig) ->
    true;
restart_required({ok, #{config := PreviousConfig}}, NewConfig) ->
    restart_projection(PreviousConfig) =/= restart_projection(NewConfig).

restart_projection(Config) ->
    maps:without(?NON_RESTART_FIELDS, Config).

notify_reconciler(Event) ->
    vpn_peer_reconciler:notify(Event).
