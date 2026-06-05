-module(vpn_tests).

-include_lib("eunit/include/eunit.hrl").

api_stubs_test() ->
    ?assertMatch({error, not_implemented}, vpn_udp:open([])),
    ?assertMatch({error, not_implemented}, vpn_peer:new([])).

vpn_tun_exports_test() ->
    ?assertMatch({module, vpn_tun}, code:ensure_loaded(vpn_tun)),
    ?assert(erlang:function_exported(vpn_tun, open, 2)),
    ?assert(erlang:function_exported(vpn_tun, close, 1)),
    ?assert(erlang:function_exported(vpn_tun, devname, 1)),
    ?assert(erlang:function_exported(vpn_tun, start_link, 2)),
    ?assert(erlang:function_exported(vpn_tun, stop, 1)).
