-module(vpn_session_config_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

validated_ovpn_is_mapped_to_runtime_peer_config_test() ->
    with_session_fixture(
      fun(OvpnPath, _Root) ->
          Runtime = runtime_config(),
          {ok, Session} = vpn_session_config:load(OvpnPath, Runtime),
          PeerConfig = maps:get(peer_config, Session),
          ?assertEqual(peer_a, maps:get(id, PeerConfig)),
          ?assertEqual(tun, maps:get(mode, PeerConfig)),
          ?assertEqual("127.0.0.1", maps:get(remote_ip, PeerConfig)),
          ?assertEqual(5556, maps:get(remote_udp_port, PeerConfig)),
          ?assertEqual(filename:absname(OvpnPath), maps:get(ovpn_path, PeerConfig)),
          ?assertEqual(true,
                       maps:get(identity_ready,
                                maps:get(ovpn_identity, PeerConfig))),
          ?assertEqual(#{host => <<"127.0.0.1">>, port => 5556, transport => udp},
                       maps:get(endpoint, Session)),
          Safe = vpn_session_config:safe_info(Session),
          ?assertNot(maps:is_key(peer_config, Safe)),
          ?assertNot(contains_key(ca_pem, Safe)),
          ?assertNot(contains_key(certificate_pem, Safe))
      end).

missing_runtime_value_is_rejected_before_identity_loading_test() ->
    ?assertEqual({error, {missing_runtime_key, psk}},
                 vpn_session_config:load("missing.ovpn",
                                         maps:remove(psk, runtime_config()))).

configured_sessions_are_combined_with_legacy_peers_test() ->
    with_session_fixture(
      fun(OvpnPath, _Root) ->
          Legacy = (runtime_config())#{certificate_path => "legacy.crt",
                                    private_key_path => "legacy.key",
                                    ca_certificate_path => "ca.crt"},
          SessionSpec = (runtime_config())#{id => peer_b,
                                         ovpn_path => OvpnPath},
          application:set_env(vpn, peers, [Legacy]),
          application:set_env(vpn, ovpn_sessions, [SessionSpec]),
          try
              {ok, [LegacyResult, SessionResult]} = vpn_session_config:configured_peers(),
              ?assertEqual(peer_a, maps:get(id, LegacyResult)),
              ?assertEqual(peer_b, maps:get(id, SessionResult)),
              ?assert(maps:is_key(ovpn_identity, SessionResult))
          after
              application:unset_env(vpn, peers),
              application:unset_env(vpn, ovpn_sessions)
          end
      end).

invalid_session_is_reported_with_its_id_test() ->
    application:set_env(vpn, peers, []),
    application:set_env(vpn, ovpn_sessions,
                        [(runtime_config())#{id => broken, ovpn_path => "missing.ovpn"}]),
    try
        ?assertMatch({error, {invalid_ovpn_session, broken,
                              {ovpn_identity_failed, _}}},
                     vpn_session_config:configured_peers())
    after
        application:unset_env(vpn, peers),
        application:unset_env(vpn, ovpn_sessions)
    end.

with_session_fixture(Fun) ->
    Root = temp_root(),
    Keys = filename:join(Root, "keys"),
    ok = file:make_dir(Root),
    ok = file:make_dir(Keys),
    copy_fixture("ec_client.key", filename:join(Keys, "client.key")),
    OvpnPath = filename:join(Root, "client.ovpn"),
    ok = file:write_file(OvpnPath, envelope()),
    try Fun(OvpnPath, Root)
    after remove_tree(Root)
    end.

runtime_config() ->
    #{id => peer_a,
      name => <<"Peer A">>,
      ifname => <<"tun0">>,
      ip => "10.20.20.1",
      local_udp_port => 5555,
      remote_peer_id => peer_b,
      psk => <<"0123456789abcdef0123456789abcdef">>}.

envelope() ->
    {ok, CaPem} = file:read_file(fixture_path("ec_ca.crt")),
    {ok, CertPem} = file:read_file(fixture_path("ec_client.crt")),
    iolist_to_binary([
        "client\n",
        "dev tun\n",
        "proto udp\n",
        "remote 127.0.0.1 5556\n",
        "nobind\n",
        "persist-key\n",
        "persist-tun\n",
        "remote-cert-tls server\n",
        "<ca>\n", CaPem, "</ca>\n",
        "<cert>\n", CertPem, "</cert>\n",
        "key keys/client.key\n"
    ]).

copy_fixture(Name, Destination) ->
    {ok, Binary} = file:read_file(fixture_path(Name)),
    ok = file:write_file(Destination, Binary),
    ok = file:change_mode(Destination, 8#600).

fixture_path(Name) ->
    filename:join([code:priv_dir(vpn), "test_identity", Name]).

temp_root() ->
    filename:join(os:getenv("TMPDIR", "/tmp"),
                  lists:flatten(io_lib:format("vpn-session-config-~p-~p",
                                              [erlang:system_time(microsecond),
                                               erlang:unique_integer([positive])]))).

contains_key(Key, Map) when is_map(Map) ->
    maps:is_key(Key, Map) orelse
        lists:any(fun(Value) -> contains_key(Key, Value) end, maps:values(Map));
contains_key(Key, List) when is_list(List) ->
    lists:any(fun(Value) -> contains_key(Key, Value) end, List);
contains_key(_Key, _Value) ->
    false.

remove_tree(Path) ->
    case file:list_dir(Path) of
        {ok, Entries} ->
            lists:foreach(
              fun(Entry) ->
                  Child = filename:join(Path, Entry),
                  case file:read_link_info(Child) of
                      {ok, #file_info{type = directory}} -> remove_tree(Child);
                      {ok, _} -> file:delete(Child);
                      {error, _} -> ok
                  end
              end,
              Entries),
            file:del_dir(Path);
        {error, _} -> ok
    end.
