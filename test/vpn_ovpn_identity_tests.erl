-module(vpn_ovpn_identity_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

real_ec_p384_identity_is_loaded_test() ->
    with_identity_fixture(
      fun(OvpnPath, _Root) ->
          {ok, Identity} = vpn_ovpn_identity:load(OvpnPath),
          ?assertEqual(true, maps:get(trusted, Identity)),
          ?assertEqual(true, maps:get(key_match, Identity)),
          ?assertEqual(true, maps:get(identity_ready, Identity)),
          ?assertEqual(64, byte_size(maps:get(certificate_fingerprint, Identity))),
          ?assertEqual(64, byte_size(maps:get(ca_fingerprint, Identity))),
          ?assertEqual(filename:join(filename:dirname(OvpnPath), "keys/client.key"),
                       maps:get(private_key_path, Identity))
      end).

safe_info_does_not_expose_public_pem_or_private_key_test() ->
    with_identity_fixture(
      fun(OvpnPath, _Root) ->
          {ok, Identity} = vpn_ovpn_identity:load(OvpnPath),
          Safe = vpn_ovpn_identity:safe_info(Identity),
          ?assertEqual(true, maps:get(identity_ready, Safe)),
          ?assertNot(maps:is_key(config, Safe)),
          ?assertNot(maps:is_key(ca_pem, Safe)),
          ?assertNot(maps:is_key(certificate_pem, Safe)),
          ?assertNot(maps:is_key(private_key_pem, Safe))
      end).

mismatched_ec_private_key_is_rejected_test() ->
    with_identity_fixture(
      fun(OvpnPath, Root) ->
          copy_fixture("ec_other.key", filename:join([Root, "keys", "client.key"])),
          ?assertEqual({error, key_mismatch}, vpn_ovpn_identity:load(OvpnPath))
      end).

missing_private_key_is_reported_test() ->
    with_identity_fixture(
      fun(OvpnPath, Root) ->
          ok = file:delete(filename:join([Root, "keys", "client.key"])),
          ?assertMatch({error, {private_key_read_failed, _, enoent}},
                       vpn_ovpn_identity:load(OvpnPath))
      end).

private_key_reference_is_resolved_from_ovpn_directory_test() ->
    with_identity_fixture(
      fun(OvpnPath, _Root) ->
          Previous = file:get_cwd(),
          ok = file:set_cwd("/tmp"),
          try
              {ok, Identity} = vpn_ovpn_identity:load(OvpnPath),
              ?assertEqual(true, maps:get(identity_ready, Identity))
          after
              {ok, OldCwd} = Previous,
              ok = file:set_cwd(OldCwd)
          end
      end).

private_key_symlink_is_rejected_test() ->
    with_identity_fixture(
      fun(OvpnPath, Root) ->
          KeyPath = filename:join([Root, "keys", "client.key"]),
          TargetPath = filename:join(Root, "target.key"),
          ok = file:rename(KeyPath, TargetPath),
          case file:make_symlink(TargetPath, KeyPath) of
              ok ->
                  ?assertEqual({error, private_key_symlink_forbidden},
                               vpn_ovpn_identity:load(OvpnPath));
              {error, enotsup} ->
                  ok
          end
      end).

insecure_private_key_permissions_are_rejected_test() ->
    with_identity_fixture(
      fun(OvpnPath, Root) ->
          KeyPath = filename:join([Root, "keys", "client.key"]),
          ok = file:change_mode(KeyPath, 8#644),
          ?assertEqual({error, insecure_private_key_permissions},
                       vpn_ovpn_identity:load(OvpnPath))
      end).

parser_failures_are_wrapped_test() ->
    Root = temp_root(),
    ok = file:make_dir(Root),
    OvpnPath = filename:join(Root, "bad.ovpn"),
    ok = file:write_file(OvpnPath, <<"client\n">>),
    try
        ?assertMatch({error, {ovpn_parse_failed, _}},
                     vpn_ovpn_identity:load(OvpnPath))
    after
        remove_tree(Root)
    end.

with_identity_fixture(Fun) ->
    Root = temp_root(),
    Keys = filename:join(Root, "keys"),
    ok = file:make_dir(Root),
    ok = file:make_dir(Keys),
    copy_fixture("ec_client.key", filename:join(Keys, "client.key")),
    OvpnPath = filename:join(Root, "client.ovpn"),
    ok = file:write_file(OvpnPath, envelope()),
    try
        Fun(OvpnPath, Root)
    after
        remove_tree(Root)
    end.

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
    ok = file:change_mode(Destination, 8#600),
    ok.

fixture_path(Name) ->
    filename:join([code:priv_dir(vpn), "test_identity", Name]).

temp_root() ->
    filename:join(os:getenv("TMPDIR", "/tmp"),
                  lists:flatten(io_lib:format("vpn-ovpn-identity-~p-~p",
                                              [erlang:system_time(microsecond),
                                               erlang:unique_integer([positive])]))).

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
        {error, _} ->
            ok
    end.
