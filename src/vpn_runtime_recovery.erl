%%%-------------------------------------------------------------------
%% @doc Reconstruct trusted runtime peer configuration from durable projection.
%%
%% Recovery runs inside vpn_peer_registry:init/1 after the allocator has restored
%% its reservations and before vpn_peer_sup starts. Only applied active heads are
%% started. Restrictive or incomplete pending heads are recovered fail-closed:
%% disabled/revoked peers remain configured but stopped, while active/removed
%% pending heads are suppressed until the matching provisioning command resumes.
%%%-------------------------------------------------------------------
-module(vpn_runtime_recovery).

-export([restore/1]).

-spec restore([map()]) -> {ok, [map()], map()} | {error, term()}.
restore(BootstrapPeers) when is_list(BootstrapPeers) ->
    case bootstrap_configs(BootstrapPeers) of
        {ok, Bootstrap} ->
            case vpn_provisioning:recovery_heads() of
                {ok, Heads} ->
                    State0 = #{configs => Bootstrap,
                               bootstrap_peers => map_size(Bootstrap),
                               durable_heads => map_size(Heads),
                               restored => [],
                               suppressed => [],
                               dynamic_pairs => 0,
                               released_pairs => 0,
                               stale_dynamic_heads => 0,
                               pending_heads => count_pending(Heads)},
                    case restore_heads(lists:sort(maps:to_list(Heads)), State0) of
                        {ok, State} ->
                            Configs = sorted_configs(maps:get(configs, State)),
                            {ok, Configs, recovery_summary(State, Configs)};
                        {error, _} = Error ->
                            Error
                    end;
                {error, Reason} ->
                    {error, {durable_provisioning_recovery_failed, Reason}}
            end;
        {error, _} = Error ->
            Error
    end;
restore(_BootstrapPeers) ->
    {error, invalid_bootstrap_peer_configs}.

bootstrap_configs(Peers) ->
    bootstrap_configs(Peers, #{}).

bootstrap_configs([], Acc) ->
    {ok, Acc};
bootstrap_configs([#{id := PeerId} = Config | Rest], Acc)
  when is_atom(PeerId); is_binary(PeerId) ->
    case maps:is_key(PeerId, Acc) of
        true ->
            {error, {duplicate_bootstrap_peer_id, PeerId}};
        false ->
            BootstrapConfig =
                Config#{provisioning_source =>
                            maps:get(provisioning_source,
                                     Config,
                                     bootstrap_sys_config)},
            bootstrap_configs(Rest, Acc#{PeerId => BootstrapConfig})
    end;
bootstrap_configs([_Invalid | _Rest], _Acc) ->
    {error, invalid_bootstrap_peer_config}.

restore_heads([], State) ->
    {ok, State};
restore_heads([{PeerId, Head} | Rest], State0) ->
    case restore_head(PeerId, Head, State0) of
        {ok, State1} -> restore_heads(Rest, State1);
        {error, Reason} -> {error, {runtime_recovery_failed, PeerId, Reason}}
    end.

restore_head(PeerId, #{dynamic_device_id := DeviceId} = Head, State) ->
    restore_dynamic_head(PeerId, DeviceId, Head, State);
restore_head(PeerId, Head, State) ->
    restore_static_head(PeerId, Head, State).

restore_static_head(PeerId, Head, State0) ->
    case recovery_mode(Head) of
        suppress ->
            {ok, suppress_ids([PeerId], State0)};
        Mode ->
            Configs = maps:get(configs, State0),
            Desired = maps:get(desired_state, Head, #{}),
            ResolutionDesired = runtime_resolution_desired(Mode, Desired),
            case static_base_config(PeerId, ResolutionDesired, Configs) of
                {ok, Base} ->
                    Config0 = maps:merge(Base, Desired),
                    Config1 = maps:merge(Config0#{id => PeerId}, head_metadata(Head)),
                    Config = apply_static_lifecycle(Mode, Desired, Config1),
                    {ok, restore_configs([Config], State0)};
                {error, Reason} ->
                    {error, Reason}
            end
    end.

static_base_config(PeerId, Desired, Configs) ->
    case maps:find(PeerId, Configs) of
        {ok, Config} ->
            case maps:get(allocation_id, Config, undefined) of
                undefined -> {ok, Config};
                _ -> {error, durable_peer_ownership_mismatch}
            end;
        error ->
            case vpn_runtime_config_resolver:resolve(PeerId, Desired) of
                {ok, Config} -> {ok, Config};
                {error, Reason} ->
                    {error, {runtime_config_recovery_failed, Reason}};
                Other ->
                    {error, {invalid_runtime_config_recovery_result, Other}}
            end
    end.

restore_dynamic_head(PeerId, DeviceId, Head, State0) ->
    case vpn_peer_allocator:lookup(DeviceId) of
        {ok, Allocation} ->
            case maps:get(device_id, Allocation, undefined) =:= DeviceId of
                false ->
                    {error, dynamic_allocation_device_mismatch};
                true ->
                    case maps:get(client_peer_id,
                                  Allocation,
                                  undefined) of
                        PeerId ->
                            restore_dynamic_allocation(
                              Allocation,
                              Head,
                              State0);
                        _CurrentClientId ->
                            %% A completed decommission followed by a new
                            %% reservation can leave the old peer-keyed ledger
                            %% head behind. The allocator owns current Device
                            %% identity, so the stale head is suppressed rather
                            %% than rebound to the new generation.
                            State1 = suppress_ids([PeerId], State0),
                            {ok, increment_stale_dynamic_heads(State1)}
                    end
            end;
        {error, not_found} ->
            restore_released_dynamic_head(PeerId, DeviceId, State0);
        {error, Reason} ->
            {error, {dynamic_allocation_lookup_failed, Reason}}
    end.

restore_released_dynamic_head(PeerId, DeviceId, State0) ->
    case vpn_peer_allocator:released(DeviceId) of
        {ok, Released} ->
            case validate_dynamic_head(PeerId, DeviceId, Released) of
                ok ->
                    ClientId = maps:get(client_peer_id, Released),
                    GatewayId = maps:get(gateway_peer_id, Released),
                    case validate_dynamic_collisions(
                           [ClientId, GatewayId],
                           Released,
                           State0) of
                        ok ->
                            State1 = suppress_ids(
                                       [ClientId, GatewayId],
                                       State0),
                            {ok,
                             increment_released_pairs(
                               increment_dynamic_pairs(State1))};
                        {error, _} = Error ->
                            Error
                    end;
                {error, _} = Error ->
                    Error
            end;
        {error, not_found} ->
            {error, {dynamic_allocation_missing, DeviceId}};
        {error, Reason} ->
            {error, {dynamic_release_barrier_lookup_failed, Reason}}
    end.

validate_dynamic_head(PeerId, DeviceId, Allocation) ->
    case {maps:get(device_id, Allocation, undefined) =:= DeviceId,
          maps:get(client_peer_id, Allocation, undefined) =:= PeerId} of
        {true, true} -> ok;
        {false, _} -> {error, dynamic_allocation_device_mismatch};
        {_, false} -> {error, dynamic_allocation_client_mismatch}
    end.

restore_dynamic_allocation(Allocation, Head, State0) ->
    ClientId = maps:get(client_peer_id, Allocation),
    GatewayId = maps:get(gateway_peer_id, Allocation),
    case validate_dynamic_collisions([ClientId, GatewayId], Allocation, State0) of
        ok ->
            case recovery_mode(Head) of
                suppress ->
                    State1 = suppress_ids([ClientId, GatewayId], State0),
                    {ok, increment_dynamic_pairs(State1)};
                Mode ->
                    DeviceId = maps:get(device_id, Allocation),
                    Desired = maps:get(desired_state, Head, #{}),
                    ResolutionDesired = runtime_resolution_desired(Mode, Desired),
                    case vpn_runtime_config_resolver:resolve_pair(DeviceId,
                                                                   ResolutionDesired) of
                        {ok, #{client := Client0, gateway := Gateway0}} ->
                            Metadata = head_metadata(Head),
                            Client1 = maps:merge(Client0, Metadata),
                            Gateway1 = maps:merge(Gateway0, Metadata),
                            Client = apply_dynamic_client_lifecycle(
                                       Mode, Desired, Client1),
                            Gateway = apply_dynamic_gateway_lifecycle(
                                        Mode, Gateway1),
                            State1 = restore_configs([Gateway, Client], State0),
                            {ok, increment_dynamic_pairs(State1)};
                        {error, Reason} ->
                            {error, {dynamic_runtime_config_recovery_failed,
                                     Reason}};
                        Other ->
                            {error, {invalid_dynamic_runtime_recovery_result,
                                     Other}}
                    end
            end;
        {error, _} = Error ->
            Error
    end.

validate_dynamic_collisions([], _Allocation, _State) ->
    ok;
validate_dynamic_collisions([PeerId | Rest], Allocation, State) ->
    Configs = maps:get(configs, State),
    case maps:find(PeerId, Configs) of
        error ->
            validate_dynamic_collisions(Rest, Allocation, State);
        {ok, Existing} ->
            AllocationId = maps:get(allocation_id, Allocation),
            DeviceId = maps:get(device_id, Allocation),
            case maps:get(allocation_id, Existing, undefined) =:= AllocationId
                 andalso
                 maps:get(device_id, Existing, undefined) =:= DeviceId of
                true -> validate_dynamic_collisions(Rest, Allocation, State);
                false -> {error, {dynamic_peer_recovery_collision, PeerId}}
            end
    end.

recovery_mode(#{phase := pending, lifecycle_state := active}) ->
    suppress;
recovery_mode(#{phase := pending, lifecycle_state := removed}) ->
    suppress;
recovery_mode(#{lifecycle_state := active}) ->
    active;
recovery_mode(#{lifecycle_state := disabled}) ->
    disabled;
recovery_mode(#{lifecycle_state := revoked}) ->
    revoked;
recovery_mode(#{lifecycle_state := removed}) ->
    suppress.

%% Runtime resolvers validate configs as if they were about to be started and
%% therefore reject policy-denied desired state. Disabled and revoked durable
%% heads still have to be materialized so the registry can restore them in a
%% stopped state. Use an ephemeral permissive authorization only while resolving
%% trusted transport/identity fields; the original desired state is merged back
%% and its restrictive lifecycle is applied before the config is exposed.
%% Active heads keep their original authorization and continue to fail closed.
runtime_resolution_desired(active, Desired) ->
    Desired;
runtime_resolution_desired(disabled, Desired) ->
    stopped_runtime_resolution_desired(Desired);
runtime_resolution_desired(revoked, Desired) ->
    stopped_runtime_resolution_desired(Desired).

stopped_runtime_resolution_desired(Desired) ->
    Desired#{authorized => true,
             authorization_reason => durable_recovery_materialization,
             enabled => true,
             revoked => false}.

head_metadata(Head) ->
    #{revision => maps:get(revision, Head),
      provisioning_source => maps:get(source, Head),
      last_provisioning_operation => maps:get(operation, Head),
      updated_at => maps:get(updated_at, Head)}.

apply_static_lifecycle(active, _Desired, Config) ->
    Config#{enabled => true,
            revoked => false};
apply_static_lifecycle(disabled, _Desired, Config) ->
    Config#{enabled => false};
apply_static_lifecycle(revoked, Desired, Config) ->
    Config#{enabled => false,
            authorized => false,
            authorization_reason =>
                maps:get(authorization_reason, Desired, revoked),
            revoked => true}.

apply_dynamic_client_lifecycle(active, _Desired, Config) ->
    Config#{enabled => true,
            revoked => false};
apply_dynamic_client_lifecycle(disabled, _Desired, Config) ->
    Config#{enabled => false};
apply_dynamic_client_lifecycle(revoked, Desired, Config) ->
    Config#{enabled => false,
            authorized => false,
            authorization_reason =>
                maps:get(authorization_reason, Desired, revoked),
            revoked => true}.

apply_dynamic_gateway_lifecycle(active, Config) ->
    Config#{enabled => true};
apply_dynamic_gateway_lifecycle(disabled, Config) ->
    Config#{enabled => false};
apply_dynamic_gateway_lifecycle(revoked, Config) ->
    Config#{enabled => false}.

restore_configs(Configs, State0) ->
    Existing = maps:get(configs, State0),
    Updated = lists:foldl(
                fun(#{id := PeerId} = Config, Acc) ->
                        Acc#{PeerId => Config}
                end,
                Existing,
                Configs),
    Restored = [maps:get(id, Config) || Config <- Configs] ++
               maps:get(restored, State0),
    State0#{configs => Updated, restored => Restored}.

suppress_ids(PeerIds, State0) ->
    Configs0 = maps:get(configs, State0),
    Configs = lists:foldl(fun maps:remove/2, Configs0, PeerIds),
    State0#{configs => Configs,
            suppressed => PeerIds ++ maps:get(suppressed, State0)}.

increment_dynamic_pairs(State) ->
    State#{dynamic_pairs => maps:get(dynamic_pairs, State) + 1}.

increment_released_pairs(State) ->
    State#{released_pairs => maps:get(released_pairs, State) + 1}.

increment_stale_dynamic_heads(State) ->
    State#{stale_dynamic_heads =>
               maps:get(stale_dynamic_heads, State) + 1}.

count_pending(Heads) ->
    length([ok || {_PeerId, Head} <- maps:to_list(Heads),
                  maps:get(phase, Head, applied) =:= pending]).

sorted_configs(Configs) ->
    lists:sort(fun(#{id := A}, #{id := B}) -> A =< B end,
               maps:values(Configs)).

recovery_summary(State, Configs) ->
    #{state => recovered,
      persistence => durable,
      bootstrap_peers => maps:get(bootstrap_peers, State),
      durable_heads => maps:get(durable_heads, State),
      pending_heads => maps:get(pending_heads, State),
      dynamic_pairs => maps:get(dynamic_pairs, State),
      released_pairs => maps:get(released_pairs, State),
      stale_dynamic_heads => maps:get(stale_dynamic_heads, State),
      configured_peers => [maps:get(id, Config) || Config <- Configs],
      restored_peers => lists:usort(maps:get(restored, State)),
      suppressed_peers => lists:usort(maps:get(suppressed, State))}.
