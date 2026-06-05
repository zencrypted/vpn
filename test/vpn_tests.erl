-module(vpn_tests).

-include_lib("eunit/include/eunit.hrl").

api_stubs_test() ->
    ?assertMatch({error, not_implemented}, vpn_tun:open([])),
    ?assertMatch({error, not_implemented}, vpn_udp:open([])),
    ?assertMatch({error, not_implemented}, vpn_peer:new([])).
