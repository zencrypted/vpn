-module(vpn_tests).

-include_lib("eunit/include/eunit.hrl").

vpn_peer_exports_test() ->
    ?assertMatch({module, vpn_peer}, code:ensure_loaded(vpn_peer)),
    ?assert(erlang:function_exported(vpn_peer, start_link, 1)),
    ?assert(erlang:function_exported(vpn_peer, stop, 1)),
    ?assert(erlang:function_exported(vpn_peer, stats, 1)),
    ?assert(erlang:function_exported(vpn_peer, reset_stats, 1)),
    ?assert(erlang:function_exported(vpn_peer, identity, 1)),
    ?assert(erlang:function_exported(vpn_peer, identity_info, 1)),
    ?assert(erlang:function_exported(vpn_peer, config, 1)).

vpn_identity_exports_test() ->
    ?assertMatch({module, vpn_identity}, code:ensure_loaded(vpn_identity)),
    ?assert(erlang:function_exported(vpn_identity, load, 1)),
    ?assert(erlang:function_exported(vpn_identity, safe_info, 1)),
    ?assert(erlang:function_exported(vpn_identity, verify_key_match, 1)).

vpn_trust_store_exports_test() ->
    ?assertMatch({module, vpn_trust_store}, code:ensure_loaded(vpn_trust_store)),
    ?assert(erlang:function_exported(vpn_trust_store, load, 1)),
    ?assert(erlang:function_exported(vpn_trust_store, verify, 2)).

vpn_manager_exports_test() ->
    ?assertMatch({module, vpn_manager}, code:ensure_loaded(vpn_manager)),
    ?assert(erlang:function_exported(vpn_manager, list_peers, 0)),
    ?assert(erlang:function_exported(vpn_manager, running_peers, 0)),
    ?assert(erlang:function_exported(vpn_manager, status, 0)),
    ?assert(erlang:function_exported(vpn_manager, peer_status, 1)),
    ?assert(erlang:function_exported(vpn_manager, certificates, 0)),
    ?assert(erlang:function_exported(vpn_manager, certificate_info, 1)),
    ?assert(erlang:function_exported(vpn_manager, certificate_status, 1)),
    ?assert(erlang:function_exported(vpn_manager, peer_info, 1)),
    ?assert(erlang:function_exported(vpn_manager, peer_stats, 1)),
    ?assert(erlang:function_exported(vpn_manager, start_peer, 1)),
    ?assert(erlang:function_exported(vpn_manager, stop_peer, 1)),
    ?assert(erlang:function_exported(vpn_manager, reload_config, 0)),
    ?assert(erlang:function_exported(vpn_manager, peer_running, 1)),
    ?assert(erlang:function_exported(vpn_manager, find_peer, 1)).

vpn_peer_sup_exports_test() ->
    ?assertMatch({module, vpn_peer_sup}, code:ensure_loaded(vpn_peer_sup)),
    ?assert(erlang:function_exported(vpn_peer_sup, start_link, 0)),
    ?assert(erlang:function_exported(vpn_peer_sup, start_peer, 1)),
    ?assert(erlang:function_exported(vpn_peer_sup, stop_peer, 1)).

vpn_tun_exports_test() ->
    ?assertMatch({module, vpn_tun}, code:ensure_loaded(vpn_tun)),
    ?assert(erlang:function_exported(vpn_tun, open, 2)),
    ?assert(erlang:function_exported(vpn_tun, open, 3)),
    ?assert(erlang:function_exported(vpn_tun, close, 1)),
    ?assert(erlang:function_exported(vpn_tun, devname, 1)),
    ?assert(erlang:function_exported(vpn_tun, write, 2)),
    ?assert(erlang:function_exported(vpn_tun, start_link, 2)),
    ?assert(erlang:function_exported(vpn_tun, start_link, 3)),
    ?assert(erlang:function_exported(vpn_tun, start_link, 4)),
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
    ?assert(erlang:function_exported(vpn_link, start_link, 6)),
    ?assert(erlang:function_exported(vpn_link, start_link, 8)),
    ?assert(erlang:function_exported(vpn_link, start_link, 9)),
    ?assert(erlang:function_exported(vpn_link, stop, 1)),
    ?assert(erlang:function_exported(vpn_link, stats, 1)),
    ?assert(erlang:function_exported(vpn_link, reset_stats, 1)),
    ?assert(erlang:function_exported(vpn_link, validate_frame_peer_id, 2)).

vpn_crypto_exports_test() ->
    ?assertMatch({module, vpn_crypto}, code:ensure_loaded(vpn_crypto)),
    ?assert(erlang:function_exported(vpn_crypto, new, 2)),
    ?assert(erlang:function_exported(vpn_crypto, encode, 2)),
    ?assert(erlang:function_exported(vpn_crypto, decode, 2)).

vpn_frame_exports_test() ->
    ?assertMatch({module, vpn_frame}, code:ensure_loaded(vpn_frame)),
    ?assert(erlang:function_exported(vpn_frame, encode, 3)),
    ?assert(erlang:function_exported(vpn_frame, decode, 1)).

vpn_udp_sink_exports_test() ->
    ?assertMatch({module, vpn_udp_sink}, code:ensure_loaded(vpn_udp_sink)),
    ?assert(erlang:function_exported(vpn_udp_sink, start_link, 1)),
    ?assert(erlang:function_exported(vpn_udp_sink, stop, 1)).
