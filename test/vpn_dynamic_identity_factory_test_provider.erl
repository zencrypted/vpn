-module(vpn_dynamic_identity_factory_test_provider).

-export([ensure/1, lookup/1]).

ensure(Allocation) when is_map(Allocation) ->
    AllocationId = maps:get(allocation_id, Allocation, undefined),
    case application:get_env(vpn, dynamic_identity_test_bundle) of
        {ok, #{allocation_id := AllocationId} = Bundle} -> {ok, Bundle};
        {ok, _Other} -> {error, allocation_mismatch};
        undefined -> {error, not_found}
    end;
ensure(_Allocation) ->
    {error, invalid_allocation}.

lookup(AllocationId) ->
    case application:get_env(vpn, dynamic_identity_test_bundle) of
        {ok, #{allocation_id := AllocationId} = Bundle} -> {ok, Bundle};
        {ok, _Other} -> {error, allocation_mismatch};
        undefined -> {error, not_found}
    end.
