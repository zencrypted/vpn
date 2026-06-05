-module(vpn_tests).

-include_lib("eunit/include/eunit.hrl").

api_stubs_test() ->
    ?assertMatch({error, not_implemented}, vpn_peer:new([])).

vpn_tun_exports_test() ->
    ?assertMatch({module, vpn_tun}, code:ensure_loaded(vpn_tun)),
    ?assert(erlang:function_exported(vpn_tun, open, 2)),
    ?assert(erlang:function_exported(vpn_tun, close, 1)),
    ?assert(erlang:function_exported(vpn_tun, devname, 1)),
    ?assert(erlang:function_exported(vpn_tun, write, 2)),
    ?assert(erlang:function_exported(vpn_tun, start_link, 2)),
    ?assert(erlang:function_exported(vpn_tun, start_link, 3)),
    ?assert(erlang:function_exported(vpn_tun, stop, 1)).

vpn_udp_exports_test() ->
    ?assertMatch({module, vpn_udp}, code:ensure_loaded(vpn_udp)),
    ?assert(erlang:function_exported(vpn_udp, start_link, 1)),
    ?assert(erlang:function_exported(vpn_udp, start_link, 2)),
    ?assert(erlang:function_exported(vpn_udp, stop, 1)),
    ?assert(erlang:function_exported(vpn_udp, send, 4)).

vpn_link_exports_test() ->
    ?assertMatch({module, vpn_link}, code:ensure_loaded(vpn_link)),
    ?assert(erlang:function_exported(vpn_link, start_link, 5)),
    ?assert(erlang:function_exported(vpn_link, stop, 1)),
    ?assert(erlang:function_exported(vpn_link, stats, 1)),
    ?assert(erlang:function_exported(vpn_link, reset_stats, 1)).

vpn_udp_sink_exports_test() ->
    ?assertMatch({module, vpn_udp_sink}, code:ensure_loaded(vpn_udp_sink)),
    ?assert(erlang:function_exported(vpn_udp_sink, start_link, 1)),
    ?assert(erlang:function_exported(vpn_udp_sink, stop, 1)).
