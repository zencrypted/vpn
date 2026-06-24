%%%-------------------------------------------------------------------
%% @doc Materializes one reserved dynamic client/gateway pair into runtime.
%%
%% Reservation remains explicit and VPN-owned. This module consumes an active
%% allocation, ensures its development identity bundle, resolves both runtime
%% configurations, writes them to the registry as one batch, and waits until
%% both certificate-control handshakes are established.
%%%-------------------------------------------------------------------
-module(vpn_dynamic_pair).

-export([ensure/2, status/1, await_established/1, await_stopped/1]).

ensure(DeviceId, Desired)
  when is_binary(DeviceId), byte_size(DeviceId) > 0, is_map(Desired) ->
    case vpn_peer_allocator:lookup(DeviceId) of
        {ok, Allocation} ->
            ensure_allocated_pair(Allocation, Desired);
        {error, not_found} ->
            {error, {dynamic_peer_allocation_required, DeviceId}};
        {error, _} = Error ->
            Error
    end;
ensure(_DeviceId, _Desired) ->
    {error, invalid_dynamic_pair_request}.

status(DeviceId) when is_binary(DeviceId), byte_size(DeviceId) > 0 ->
    case vpn_peer_allocator:lookup(DeviceId) of
        {ok, Allocation} ->
            {ok, pair_status(Allocation)};
        {error, _} = Error ->
            Error
    end;
status(_DeviceId) ->
    {error, invalid_device_id}.

await_established(DeviceId) when is_binary(DeviceId), byte_size(DeviceId) > 0 ->
    await_pair_state(DeviceId, established);
await_established(_DeviceId) ->
    {error, invalid_device_id}.

await_stopped(DeviceId) when is_binary(DeviceId), byte_size(DeviceId) > 0 ->
    await_pair_state(DeviceId, stopped);
await_stopped(_DeviceId) ->
    {error, invalid_device_id}.

await_pair_state(DeviceId, State) ->
    case vpn_peer_allocator:lookup(DeviceId) of
        {ok, Allocation} ->
            case reconcile_options() of
                {ok, Options} ->
                    ClientId = maps:get(client_peer_id, Allocation),
                    GatewayId = maps:get(gateway_peer_id, Allocation),
                    wait_for_pair_state(ClientId, GatewayId, State, Options);
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

ensure_allocated_pair(Allocation, Desired) ->
    case ensure_identity(Allocation) of
        {ok, _Bundle} ->
            case vpn_runtime_config_resolver:resolve_pair(
                   maps:get(device_id, Allocation), Desired) of
                {ok, Pair} ->
                    reconcile_pair(Allocation, Pair);
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

ensure_identity(Allocation) ->
    Provider = application:get_env(vpn,
                                   dynamic_identity_factory_module,
                                   vpn_dynamic_identity_factory),
    try Provider:ensure(Allocation) of
        {ok, _Bundle} = Ok -> Ok;
        {error, Reason} -> {error, {dynamic_identity_materialization_failed, Reason}};
        Other -> {error, {invalid_dynamic_identity_factory_result, Other}}
    catch
        Class:Reason ->
            {error, {dynamic_identity_factory_failed, Provider, Class, Reason}}
    end.

reconcile_pair(Allocation, #{client := Client0, gateway := Gateway0}) ->
    Client = Client0#{provisioning_source => dynamic_pair},
    Gateway = Gateway0#{provisioning_source => dynamic_pair},
    case validate_pair_ownership(Allocation, Client, Gateway) of
        ok ->
            case reconcile_options() of
                {ok, Options} ->
                    register_and_wait(Allocation, Client, Gateway, Options);
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

register_and_wait(Allocation, Client, Gateway, Options) ->
    ClientId = maps:get(id, Client),
    GatewayId = maps:get(id, Gateway),
    Previous = registry_snapshot([ClientId, GatewayId]),
    case pair_is_current(Client, Gateway) andalso
         pair_established(ClientId, GatewayId) of
        true ->
            {ok, (pair_status(Allocation))#{outcome => unchanged}};
        false ->
            case vpn_peer_registry:put_many([Gateway, Client]) of
                {ok, _SafeEntries} ->
                    case wait_for_established(ClientId, GatewayId, Options) of
                        ok ->
                            {ok, (pair_status(Allocation))#{outcome => reconciled}};
                        {error, _} = Error ->
                            rollback_registry([ClientId, GatewayId], Previous),
                            Error
                    end;
                {error, _} = Error ->
                    Error
            end
    end.

validate_pair_ownership(Allocation, Client, Gateway) ->
    Expected = [{maps:get(client_peer_id, Allocation), client, Client},
                {maps:get(gateway_peer_id, Allocation), gateway, Gateway}],
    case lists:all(fun({PeerId, Role, Config}) ->
                           maps:get(id, Config, undefined) =:= PeerId andalso
                           maps:get(device_id, Config, undefined) =:=
                               maps:get(device_id, Allocation) andalso
                           maps:get(allocation_id, Config, undefined) =:=
                               maps:get(allocation_id, Allocation) andalso
                           maps:get(allocation_role, Config, undefined) =:= Role
                   end,
                   Expected) of
        true -> validate_registry_ownership(Allocation, Expected);
        false -> {error, dynamic_pair_resolution_mismatch}
    end.

validate_registry_ownership(_Allocation, []) ->
    ok;
validate_registry_ownership(Allocation, [{PeerId, Role, _Config} | Rest]) ->
    case vpn_peer_registry:config(PeerId) of
        {error, not_found} ->
            validate_registry_ownership(Allocation, Rest);
        {ok, Existing} ->
            case maps:get(allocation_id, Existing, undefined) =:=
                     maps:get(allocation_id, Allocation) andalso
                 maps:get(device_id, Existing, undefined) =:=
                     maps:get(device_id, Allocation) andalso
                 maps:get(allocation_role, Existing, undefined) =:= Role of
                true -> validate_registry_ownership(Allocation, Rest);
                false -> {error, {dynamic_peer_registry_collision, PeerId}}
            end
    end.

pair_is_current(Client, Gateway) ->
    config_matches(Client) andalso config_matches(Gateway).

config_matches(Expected) ->
    PeerId = maps:get(id, Expected),
    ExpectedEnabled = maps:get(enabled, Expected, true),
    case {vpn_peer_registry:config(PeerId), vpn_peer_registry:get(PeerId)} of
        {{ok, Expected}, {ok, #{enabled := ExpectedEnabled}}} -> true;
        _ -> false
    end.

registry_snapshot(PeerIds) ->
    [{PeerId, vpn_peer_registry:config(PeerId)} || PeerId <- PeerIds].

rollback_registry(PeerIds, Previous) ->
    _ = vpn_peer_registry:remove_many(PeerIds),
    PreviousConfigs = [Config || {_PeerId, {ok, Config}} <- Previous],
    case PreviousConfigs of
        [] -> ok;
        _ -> _ = vpn_peer_registry:put_many(PreviousConfigs), ok
    end,
    _ = vpn_peer_reconciler:reconcile_now(),
    ok.

wait_for_established(ClientId, GatewayId, Options) ->
    wait_for_pair_state(ClientId, GatewayId, established, Options).

wait_for_pair_state(ClientId, GatewayId, State,
                    #{establish_timeout_ms := TimeoutMs,
                      poll_interval_ms := PollMs}) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    wait_for_pair_state(ClientId, GatewayId, State, Deadline, PollMs).

wait_for_pair_state(ClientId, GatewayId, established, Deadline, PollMs) ->
    case pair_established(ClientId, GatewayId) of
        true ->
            ok;
        false ->
            wait_or_timeout(ClientId, GatewayId, established, Deadline, PollMs)
    end;
wait_for_pair_state(ClientId, GatewayId, stopped, Deadline, PollMs) ->
    case pair_stopped(ClientId, GatewayId) of
        true ->
            ok;
        false ->
            wait_or_timeout(ClientId, GatewayId, stopped, Deadline, PollMs)
    end.

wait_or_timeout(ClientId, GatewayId, State, Deadline, PollMs) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            pair_state_timeout(ClientId, GatewayId, State);
        false ->
            timer:sleep(PollMs),
            wait_for_pair_state(ClientId, GatewayId, State, Deadline, PollMs)
    end.

pair_state_timeout(ClientId, GatewayId, established) ->
    {error,
     {dynamic_pair_establishment_timeout,
      #{client => runtime_peer_status(ClientId),
        gateway => runtime_peer_status(GatewayId)}}};
pair_state_timeout(ClientId, GatewayId, stopped) ->
    {error,
     {dynamic_pair_stop_timeout,
      #{client => runtime_peer_status(ClientId),
        gateway => runtime_peer_status(GatewayId)}}}.


pair_established(ClientId, GatewayId) ->
    maps:get(handshake_status, runtime_peer_status(ClientId), undefined) =:=
        established andalso
    maps:get(handshake_status, runtime_peer_status(GatewayId), undefined) =:=
        established.

pair_stopped(ClientId, GatewayId) ->
    maps:get(running, runtime_peer_status(ClientId), false) =:= false andalso
    maps:get(running, runtime_peer_status(GatewayId), false) =:= false.

pair_status(Allocation) ->
    ClientId = maps:get(client_peer_id, Allocation),
    GatewayId = maps:get(gateway_peer_id, Allocation),
    #{allocation_id => maps:get(allocation_id, Allocation),
      allocator_instance_id => maps:get(allocator_instance_id,
                                        Allocation,
                                        undefined),
      device_id => maps:get(device_id, Allocation),
      client_peer_id => ClientId,
      gateway_peer_id => GatewayId,
      state => maps:get(state, Allocation),
      client => public_peer_status(ClientId),
      gateway => public_peer_status(GatewayId)}.

public_peer_status(PeerId) ->
    Runtime = runtime_peer_status(PeerId),
    Registry = case vpn_peer_registry:get(PeerId) of
                   {ok, Entry} -> Entry;
                   {error, not_found} -> undefined
               end,
    Runtime#{peer_id => PeerId, registry => Registry}.

runtime_peer_status(PeerId) ->
    try vpn_manager:peer_stats(PeerId) of
        #{link := LinkStats} ->
            Handshake = maps:get(handshake, LinkStats, #{}),
            #{running => true,
              handshake_status => maps:get(status, Handshake, undefined)};
        {error, not_found} ->
            #{running => false, handshake_status => undefined};
        {error, Reason} ->
            #{running => false,
              handshake_status => undefined,
              error => Reason}
    catch
        exit:_ ->
            #{running => false, handshake_status => undefined}
    end.

reconcile_options() ->
    Defaults = #{establish_timeout_ms => 5000,
                 poll_interval_ms => 50},
    Configured = application:get_env(vpn, dynamic_pair_reconcile, #{}),
    case is_map(Configured) of
        true -> validate_reconcile_options(maps:merge(Defaults, Configured));
        false -> {error, invalid_dynamic_pair_reconcile_config}
    end.

validate_reconcile_options(#{establish_timeout_ms := TimeoutMs,
                             poll_interval_ms := PollMs} = Options)
  when is_integer(TimeoutMs), TimeoutMs > 0,
       is_integer(PollMs), PollMs > 0,
       PollMs =< TimeoutMs ->
    {ok, Options};
validate_reconcile_options(_Options) ->
    {error, invalid_dynamic_pair_reconcile_config}.
