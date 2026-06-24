-module(vpn_dynamic_identity_factory_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

identity_bundle_lifecycle_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          Allocation = allocation(<<"peer_a">>, <<"peer_b">>),
                          {ok, Bundle1} = vpn_dynamic_identity_factory:ensure(Allocation),
                          {ok, Bundle2} = vpn_dynamic_identity_factory:ensure(Allocation),
                          ?assertEqual(Bundle1, Bundle2),
                          ?assertEqual(ready, maps:get(state, Bundle1)),
                          ?assertEqual(<<"peer_a">>,
                                       maps:get(peer_id, maps:get(client, Bundle1))),
                          ?assertEqual(<<"peer_b">>,
                                       maps:get(peer_id, maps:get(gateway, Bundle1))),
                          ?assertEqual(true,
                                       maps:get(identity_ready,
                                                maps:get(client, Bundle1))),
                          ?assertEqual(true,
                                       maps:get(trusted,
                                                maps:get(gateway, Bundle1))),
                          ?assertEqual(true,
                                       maps:get(key_match,
                                                maps:get(gateway, Bundle1))),
                          ?assertEqual(nomatch,
                                       binary:match(term_to_binary(Bundle1),
                                                    <<"BEGIN PRIVATE KEY">>)),
                          {ok, Bundle3} =
                              vpn_dynamic_identity_factory:lookup(
                                maps:get(allocation_id, Allocation)),
                          ?assertEqual(Bundle1, Bundle3),
                          ?assertEqual(
                             {error, dynamic_identity_manifest_allocation_mismatch},
                             vpn_dynamic_identity_factory:ensure(
                               Allocation#{device_id => <<"other-device">>})),
                          Allocation2 = Allocation#{allocation_id =>
                                                       <<"dynamic-vpn-test-2">>,
                                                   device_id => <<"device-2">>},
                          {ok, BundleOther} =
                              vpn_dynamic_identity_factory:ensure(Allocation2),
                          ?assertEqual(ready, maps:get(state, BundleOther)),
                          ClientKey = maps:get(private_key_path,
                                               maps:get(client, Bundle1)),
                          GatewayKey = maps:get(private_key_path,
                                                maps:get(gateway, Bundle1)),
                          assert_private_mode(ClientKey),
                          assert_private_mode(GatewayKey),
                          {ok, _ReleasedOther} =
                              vpn_dynamic_identity_factory:release(
                                maps:get(allocation_id, Allocation2)),
                          {ok, Released} =
                              vpn_dynamic_identity_factory:release(
                                maps:get(allocation_id, Allocation)),
                          ?assertEqual(released, maps:get(state, Released)),
                          ?assertEqual({error, dynamic_identity_not_found},
                                       vpn_dynamic_identity_factory:lookup(
                                         maps:get(allocation_id, Allocation))),
                          ?assertNot(filelib:is_dir(maps:get(bundle_dir, Bundle1))),
                          ?assert(filelib:is_dir(maps:get(test_root, Context)))
                      end)]
     end}.

incomplete_bundle_is_rejected_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Context) ->
             [?_test(begin
                          Allocation = allocation(<<"peer_a">>, <<"peer_b">>),
                          AllocationId = binary_to_list(maps:get(allocation_id, Allocation)),
                          Root = maps:get(bundle_root, Context),
                          Partial = filename:join([Root,
                                                   AllocationId,
                                                   "keys",
                                                   "peer_a.key"]),
                          ok = filelib:ensure_dir(Partial),
                          ok = file:write_file(Partial, <<"partial">>),
                          ?assertMatch({error,
                                        {incomplete_dynamic_identity_bundle,
                                         _,
                                         _}},
                                       vpn_dynamic_identity_factory:ensure(Allocation))
                      end)]
     end}.

certificate_subject_mismatch_is_rejected_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Context) ->
             [?_test(begin
                          Allocation = allocation(<<"wrong_client">>, <<"peer_b">>),
                          ?assertMatch({error,
                                        {dynamic_client_certificate_subject_mismatch,
                                         <<"wrong_client">>,
                                         <<"peer_a">>}},
                                       vpn_dynamic_identity_factory:ensure(Allocation))
                      end)]
     end}.

factory_is_disabled_by_default_test() ->
    Previous = application:get_env(vpn, dynamic_identity_factory),
    application:unset_env(vpn, dynamic_identity_factory),
    try
        ?assertEqual({error, dynamic_identity_factory_disabled},
                     vpn_dynamic_identity_factory:ensure(
                       allocation(<<"peer_a">>, <<"peer_b">>)))
    after
        restore_env(dynamic_identity_factory, Previous)
    end.

setup() ->
    Suffix = integer_to_list(erlang:unique_integer([positive, monotonic])),
    TestRoot = filename:join("local", "identity-factory-test-" ++ Suffix),
    BundleRoot = filename:join(TestRoot, "bundles"),
    CaDir = filename:join(TestRoot, "ca"),
    application:set_env(vpn,
                        dynamic_identity_factory,
                        #{mode => development,
                          root_dir => BundleRoot,
                          ca_dir => CaDir,
                          tool_path => "tools/ensure-dynamic-identity.sh",
                          command_module => vpn_dynamic_identity_test_command}),
    #{test_root => TestRoot,
      bundle_root => BundleRoot,
      ca_dir => CaDir}.

cleanup(Context) ->
    application:unset_env(vpn, dynamic_identity_factory),
    remove_tree(maps:get(test_root, Context)),
    ok.

allocation(ClientPeerId, GatewayPeerId) ->
    #{allocation_id => <<"dynamic-vpn-test-1">>,
      device_id => <<"device test with spaces is metadata only">>,
      client_peer_id => ClientPeerId,
      gateway_peer_id => GatewayPeerId,
      client => #{peer_id => ClientPeerId,
                  remote_ip => {127,0,0,1},
                  local_udp_port => 24000},
      gateway => #{peer_id => GatewayPeerId,
                   local_udp_port => 25000}}.

assert_private_mode(Path) ->
    {ok, #file_info{mode = Mode}} = file:read_file_info(Path),
    ?assertEqual(0, Mode band 8#077).

restore_env(Key, {ok, Value}) -> application:set_env(vpn, Key, Value);
restore_env(Key, undefined) -> application:unset_env(vpn, Key).

remove_tree(Path) ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = directory}} ->
            {ok, Entries} = file:list_dir(Path),
            lists:foreach(fun(Entry) -> remove_tree(filename:join(Path, Entry)) end,
                          Entries),
            file:del_dir(Path);
        {ok, _} -> file:delete(Path);
        {error, _} -> ok
    end.
