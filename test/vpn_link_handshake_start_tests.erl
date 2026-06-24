-module(vpn_link_handshake_start_tests).

-include_lib("eunit/include/eunit.hrl").

stale_control_frames_are_drained_before_delayed_handshake_test_() ->
    {timeout,
     10,
     fun() ->
             {PortA, PortB} = distinct_udp_ports(),
             DelayMs = 500,
             OptionsA = certificate_options("peer_a", DelayMs),
             OptionsB = certificate_options("peer_b", DelayMs),
             {ok, LinkA} = vpn_link:start_link(
                             <<"hsda1">>, "10.99.0.1", tun,
                             PortA, {127, 0, 0, 1}, PortB,
                             peer_a, peer_b, undefined, OptionsA),
             {ok, LinkB} = vpn_link:start_link(
                             <<"hsdb1">>, "10.99.0.2", tun,
                             PortB, {127, 0, 0, 1}, PortA,
                             peer_b, peer_a, undefined, OptionsB),
             try
                 ok = send_stale_rekey_hellos(PortA, PortB),
                 ?assert(wait_until(fun() -> established(LinkA, LinkB) end,
                                    120,
                                    25)),
                 {ok, StateA} = vpn_link:debug_session_state(LinkA),
                 {ok, StateB} = vpn_link:debug_session_state(LinkB),
                 ?assertEqual(false,
                              maps:get(handshake_start_pending, StateA)),
                 ?assertEqual(false,
                              maps:get(handshake_start_pending, StateB)),
                 ?assertEqual(DelayMs,
                              maps:get(handshake_start_delay_ms, StateA)),
                 ?assertEqual(DelayMs,
                              maps:get(handshake_start_delay_ms, StateB)),
                 ?assert(maps:get(handshake_start_dropped_packets, StateA) > 0),
                 ?assert(maps:get(handshake_start_dropped_packets, StateB) > 0)
             after
                 stop_link(LinkA),
                 stop_link(LinkB)
             end
     end}.


link_stops_and_releases_udp_port_when_owner_is_killed_test_() ->
    {timeout,
     10,
     fun() ->
             {Port, RemotePort} = distinct_udp_ports(),
             Parent = self(),
             Owner = spawn(
                       fun() ->
                               Result = vpn_link:start_link(
                                          <<"owner-exit">>,
                                          "10.99.2.1",
                                          tun,
                                          Port,
                                          {127, 0, 0, 1},
                                          RemotePort,
                                          owner_peer,
                                          remote_peer,
                                          <<"owner-exit-psk">>,
                                          #{mode => disabled}),
                               Parent ! {owner_link_result, self(), Result},
                               receive stop -> ok end
                       end),
             LinkPid = receive
                           {owner_link_result, Owner, {ok, Pid}} -> Pid;
                           {owner_link_result, Owner, Other} ->
                               erlang:error({vpn_link_start_failed, Other})
                       after 3000 ->
                           erlang:error(vpn_link_start_timeout)
                       end,
             Monitor = erlang:monitor(process, LinkPid),
             exit(Owner, kill),
             receive
                 {'DOWN', Monitor, process, LinkPid, _Reason} -> ok
             after 3000 ->
                 erlang:error(vpn_link_orphaned_after_owner_exit)
             end,
             {ok, Socket} = gen_udp:open(Port, [binary]),
             gen_udp:close(Socket)
     end}.

invalid_handshake_start_delay_is_rejected_test() ->
    Config = #{id => peer_a,
               mode => tun,
               ifname => <<"delay-invalid">>,
               ip => "10.99.1.1",
               local_udp_port => 41000,
               remote_ip => {127, 0, 0, 1},
               remote_udp_port => 41001,
               remote_peer_id => peer_b,
               certificate_path => fixture_path("peer_a.crt"),
               private_key_path => fixture_path("peer_a.key"),
               ca_certificate_path => fixture_path("ca.crt"),
               handshake_mode => certificate_control,
               handshake_remote_ca_certificate_path => fixture_path("ca.crt"),
               handshake_start_delay_ms => -1,
               previous_epoch_grace_ms => 5000},
    ?assertEqual({error, {invalid_handshake_start_delay_ms, -1}},
                 vpn_peer:validate_runtime_config(Config)).

certificate_options(PeerName, DelayMs) ->
    CertPath = fixture_path(PeerName ++ ".crt"),
    KeyPath = fixture_path(PeerName ++ ".key"),
    {ok, CertPem} = file:read_file(CertPath),
    #{mode => certificate_control,
      local_certificate_pem => CertPem,
      local_private_key_path => KeyPath,
      remote_ca_certificate_path => fixture_path("ca.crt"),
      retry_interval => 100,
      max_retries => 20,
      start_delay_ms => DelayMs,
      previous_epoch_grace_ms => 5000,
      debug_replay_controls => true,
      auto_rekey_after_seconds => 0,
      auto_rekey_after_packets => 0}.

send_stale_rekey_hellos(PortA, PortB) ->
    {PublicA, _PrivateA} = vpn_session_kdf:generate_key_pair(),
    {PublicB, _PrivateB} = vpn_session_kdf:generate_key_pair(),
    HelloFromA = vpn_handshake_frame:encode_hello(
                   peer_a,
                   crypto:strong_rand_bytes(16),
                   crypto:strong_rand_bytes(16),
                   PublicA,
                   rekey),
    HelloFromB = vpn_handshake_frame:encode_hello(
                   peer_b,
                   crypto:strong_rand_bytes(16),
                   crypto:strong_rand_bytes(16),
                   PublicB,
                   rekey),
    {ok, Socket} = gen_udp:open(0, [binary]),
    try
        lists:foreach(
          fun(_) ->
                  ok = gen_udp:send(Socket, {127, 0, 0, 1}, PortA, HelloFromB),
                  ok = gen_udp:send(Socket, {127, 0, 0, 1}, PortB, HelloFromA)
          end,
          lists:seq(1, 3)),
        ok
    after
        gen_udp:close(Socket)
    end.

established(LinkA, LinkB) ->
    session_established(LinkA) andalso session_established(LinkB).

session_established(Link) ->
    case vpn_link:debug_session_state(Link) of
        {ok, #{handshake_status := established}} -> true;
        _ -> false
    end.

distinct_udp_ports() ->
    PortA = free_udp_port(),
    PortB = free_udp_port(),
    case PortA =:= PortB of
        true -> distinct_udp_ports();
        false -> {PortA, PortB}
    end.

free_udp_port() ->
    {ok, Socket} = gen_udp:open(0, [binary]),
    {ok, {_Address, Port}} = inet:sockname(Socket),
    gen_udp:close(Socket),
    Port.

fixture_path(Name) ->
    filename:join([code:priv_dir(vpn), "certs", Name]).

wait_until(_Fun, 0, _SleepMs) ->
    false;
wait_until(Fun, Attempts, SleepMs) ->
    case Fun() of
        true -> true;
        false -> timer:sleep(SleepMs), wait_until(Fun, Attempts - 1, SleepMs)
    end.

stop_link(Pid) when is_pid(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            _ = catch vpn_link:stop(Pid),
            ok;
        false ->
            ok
    end.
