-module(vpn_dynamic_identity_factory_test_provider).

-export([lookup/1]).

lookup(AllocationId) ->
    case application:get_env(vpn, dynamic_identity_test_bundle) of
        {ok, #{allocation_id := AllocationId} = Bundle} -> {ok, Bundle};
        {ok, _Other} -> {error, allocation_mismatch};
        undefined -> {error, not_found}
    end.
