-module(vpn_dynamic_identity_factory_test_provider).

-export([ensure/1, lookup/1, release/1]).

ensure(Allocation) when is_map(Allocation) ->
    AllocationId = maps:get(allocation_id, Allocation, undefined),
    case application:get_env(vpn, dynamic_identity_test_bundle) of
        {ok, #{allocation_id := AllocationId} = Bundle} -> {ok, Bundle};
        {ok, _Other} -> {error, allocation_mismatch};
        undefined ->
            case application:get_env(vpn, dynamic_identity_test_ensure_bundle) of
                {ok, Bundle0} when is_map(Bundle0) ->
                    Bundle = Bundle0#{allocation_id => AllocationId,
                                      device_id => maps:get(device_id, Allocation),
                                      client => (maps:get(client, Bundle0))#{
                                          peer_id => maps:get(client_peer_id, Allocation)},
                                      gateway => (maps:get(gateway, Bundle0))#{
                                          peer_id => maps:get(gateway_peer_id, Allocation)}},
                    application:set_env(vpn, dynamic_identity_test_bundle, Bundle),
                    {ok, Bundle};
                undefined ->
                    {error, not_found};
                {ok, _Other} ->
                    {error, invalid_ensure_bundle}
            end
    end;
ensure(_Allocation) ->
    {error, invalid_allocation}.

lookup(AllocationId) ->
    case application:get_env(vpn, dynamic_identity_test_bundle) of
        {ok, #{allocation_id := AllocationId} = Bundle} -> {ok, Bundle};
        {ok, _Other} -> {error, allocation_mismatch};
        undefined -> {error, not_found}
    end.

release(AllocationId) ->
    case application:get_env(vpn, dynamic_identity_test_bundle) of
        {ok, #{allocation_id := AllocationId}} ->
            application:unset_env(vpn, dynamic_identity_test_bundle),
            {ok, #{allocation_id => AllocationId, state => released}};
        {ok, _Other} ->
            {error, allocation_mismatch};
        undefined ->
            {error, not_found}
    end.
