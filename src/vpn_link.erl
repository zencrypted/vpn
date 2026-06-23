%%%-------------------------------------------------------------------
%% @doc Bidirectional TUN to UDP link.
%%%-------------------------------------------------------------------
-module(vpn_link).

-behaviour(gen_server).

-define(REPLAY_WINDOW_SIZE, 64).
-define(DEFAULT_PREVIOUS_EPOCH_GRACE_MS, 5000).
-define(DEBUG_FRAME_HISTORY_LIMIT, 256).

-export([start_link/5, start_link/6, start_link/8, start_link/9, start_link/10,
         stop/1, stats/1, reset_stats/1, rekey/1,
         debug_frame_history/1, debug_replay_frame/3, debug_send_frames/2]).
-export([validate_frame_peer_id/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

start_link(TunName, TunIp, LocalUdpPort, RemoteIp, RemoteUdpPort) ->
    start_link(TunName, TunIp, tap, LocalUdpPort, RemoteIp, RemoteUdpPort).

start_link(TunName, TunIp, Mode, LocalUdpPort, RemoteIp, RemoteUdpPort) ->
    gen_server:start_link(?MODULE,
                          {psk_required,
                           TunName,
                           TunIp,
                           Mode,
                           LocalUdpPort,
                           RemoteIp,
                           RemoteUdpPort},
                          []).

start_link(TunName,
           TunIp,
           Mode,
           LocalUdpPort,
           RemoteIp,
           RemoteUdpPort,
           PeerId,
           RemotePeerId) ->
    gen_server:start_link(?MODULE,
                          {psk_required,
                           TunName,
                           TunIp,
                           Mode,
                           LocalUdpPort,
                           RemoteIp,
                           RemoteUdpPort,
                           PeerId,
                           RemotePeerId},
                          []).

start_link(TunName,
           TunIp,
           Mode,
           LocalUdpPort,
           RemoteIp,
           RemoteUdpPort,
           PeerId,
           RemotePeerId,
           Psk) ->
    start_link(TunName, TunIp, Mode, LocalUdpPort, RemoteIp, RemoteUdpPort,
               PeerId, RemotePeerId, Psk, #{mode => disabled}).

start_link(TunName, TunIp, Mode, LocalUdpPort, RemoteIp, RemoteUdpPort,
           PeerId, RemotePeerId, Psk, HandshakeOptions) ->
    Args = {TunName, TunIp, Mode, LocalUdpPort, RemoteIp, RemoteUdpPort,
            PeerId, RemotePeerId, Psk, HandshakeOptions},
    gen_server:start_link(?MODULE, Args, []).

stop(Pid) ->
    gen_server:stop(Pid).

stats(Pid) ->
    gen_server:call(Pid, stats).

reset_stats(Pid) ->
    gen_server:call(Pid, reset_stats).

rekey(Pid) ->
    gen_server:call(Pid, rekey).

debug_frame_history(Pid) ->
    gen_server:call(Pid, debug_frame_history).

debug_replay_frame(Pid, KeyEpoch, Seq) ->
    gen_server:call(Pid, {debug_replay_frame, KeyEpoch, Seq}).

debug_send_frames(Pid, Count) ->
    gen_server:call(Pid, {debug_send_frames, Count}, 30000).

init({psk_required, _TunName, _TunIp, _Mode, _LocalUdpPort, _RemoteIp, _RemoteUdpPort}) ->
    {stop, psk_required};
init({psk_required, _TunName, _TunIp, _Mode, _LocalUdpPort, _RemoteIp, _RemoteUdpPort, _PeerId, _RemotePeerId}) ->
    {stop, psk_required};
init({TunName, TunIp, Mode, LocalUdpPort, RemoteIp, RemoteUdpPort, PeerId, RemotePeerId, Psk, HandshakeOptions}) ->
    process_flag(trap_exit, true),
    case vpn_udp:start_link(LocalUdpPort, self()) of
        {ok, UdpPid} ->
            init_tun(UdpPid, TunName, TunIp, Mode, RemoteIp, RemoteUdpPort, PeerId, RemotePeerId, Psk, HandshakeOptions);
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(stats, _From, State) ->
    {reply, stats_map(State), State};
handle_call(reset_stats, _From, State) ->
    {reply, ok, reset_counter_values(State)};
handle_call(rekey, _From, State) ->
    initiate_rekey(State);
handle_call(debug_frame_history, _From, State) ->
    case maps:get(debug_replay_enabled, State, false) of
        true -> {reply, {ok, debug_frame_history_info(State)}, State};
        false -> {reply, {error, debug_replay_disabled}, State}
    end;
handle_call({debug_replay_frame, KeyEpoch, Seq}, _From, State) ->
    replay_debug_frame(KeyEpoch, Seq, State);
handle_call({debug_send_frames, Count}, _From, State) ->
    send_debug_frames(Count, State);
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(handshake_start, State) ->
    start_handshake(State);
handle_info(handshake_retry, State) ->
    retry_handshake(State);
handle_info({vpn_tun_packet, TunPid, Packet},
            State = #{tun_pid := TunPid,
                      udp_pid := UdpPid,
                      remote_ip := RemoteIp,
                      remote_udp_port := RemoteUdpPort,
                      mode := Mode}) ->
    Kind = packet_kind(Packet, Mode),
    Size = byte_size(Packet),
    logger:info("vpn_link tun_rx kind=~p size=~p", [Kind, Size]),
    State1 = incr_counters(State, tun_rx_packets, tun_rx_bytes, Size),
    case handshake_established(State1) of
        true -> encode_and_send(Packet, Kind, Size, UdpPid, RemoteIp, RemoteUdpPort, State1);
        false ->
            logger:debug("vpn_link blocked TUN packet until handshake is established", []),
            {noreply, incr_counter(State1, handshake_blocked_packets)}
    end;
handle_info({vpn_tun_packet, _OtherTunPid, _Packet}, State) ->
    {noreply, State};
handle_info({vpn_udp_packet, UdpPid, Ip, Port, Packet},
            State = #{udp_pid := UdpPid, tun_pid := TunPid, mode := Mode}) ->
    Size = byte_size(Packet),
    logger:info("vpn_link udp_rx from ~s:~p size=~p",
                [format_ip(Ip), Port, Size]),
    State1 = incr_counters(State, udp_rx_packets, udp_rx_bytes, Size),
    case vpn_handshake_frame:is_control(Packet) of
        true -> handle_handshake_packet(Packet, State1);
        false ->
            case handshake_established(State1) of
                true -> decode_and_write(Packet, Mode, TunPid, State1);
                false ->
                    logger:warning("vpn_link dropped data packet before handshake establishment", []),
                    {noreply, incr_counter(State1, handshake_blocked_packets)}
            end
    end;
handle_info({vpn_udp_packet, _OtherUdpPid, _Ip, _Port, _Packet}, State) ->
    {noreply, State};
handle_info({expire_previous_crypto, Epoch, Token},
            State = #{previous_crypto := #{key_epoch := Epoch},
                      previous_crypto_timer_token := Token}) ->
    logger:debug("vpn_link expired previous receive key epoch ~p", [Epoch]),
    {noreply, State#{previous_crypto := undefined,
                     previous_replay_window := undefined,
                     previous_crypto_expires_at := undefined,
                     previous_crypto_timer := undefined,
                     previous_crypto_timer_token := undefined}};
handle_info({expire_previous_crypto, _Epoch, _Token}, State) ->
    {noreply, State};
handle_info({'EXIT', TunPid, Reason}, State = #{tun_pid := TunPid}) ->
    {stop, {tun_exit, Reason}, State};
handle_info({'EXIT', UdpPid, Reason}, State = #{udp_pid := UdpPid}) ->
    {stop, {udp_exit, Reason}, State};
handle_info(_Message, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    stop_worker(maps:get(tun_pid, State, undefined), fun vpn_tun:stop/1),
    stop_worker(maps:get(udp_pid, State, undefined), fun vpn_udp:stop/1),
    ok.

init_tun(UdpPid, TunName, TunIp, Mode, RemoteIp, RemoteUdpPort, PeerId, RemotePeerId, Psk, HandshakeOptions) ->
    case vpn_tun:start_link(TunName, TunIp, self(), Mode) of
        {ok, TunPid} ->
            Handshake = vpn_handshake:new(PeerId, RemotePeerId, HandshakeOptions),
            State = maps:merge(#{udp_pid => UdpPid,
                                 tun_pid => TunPid,
                                 mode => Mode,
                                 peer_id => normalize_peer_id(PeerId),
                                 remote_peer_id => normalize_peer_id(RemotePeerId),
                                 crypto => initial_crypto(Psk, normalize_peer_id(PeerId), HandshakeOptions),
                                 previous_crypto => undefined,
                                 previous_replay_window => undefined,
                                 previous_crypto_expires_at => undefined,
                                 previous_crypto_timer => undefined,
                                 previous_crypto_timer_token => undefined,
                                 previous_epoch_grace_ms =>
                                     maps:get(previous_epoch_grace_ms,
                                              HandshakeOptions,
                                              ?DEFAULT_PREVIOUS_EPOCH_GRACE_MS),
                                 debug_replay_enabled =>
                                     maps:get(debug_replay_controls,
                                              HandshakeOptions,
                                              false),
                                 debug_frame_history => [],
                                 current_replay_window => vpn_replay_window:new(?REPLAY_WINDOW_SIZE),
                                 crypto_session_id => undefined,
                                 handshake => Handshake,
                                 handshake_timer => undefined,
                                 session_lifecycle => undefined,
                                 tx_seq => 0,
                                 rx_seq => 0,
                                 remote_ip => RemoteIp,
                                 remote_udp_port => RemoteUdpPort},
                               zero_counters()),
            self() ! handshake_start,
            {ok, State};
        {error, Reason} ->
            _ = vpn_udp:stop(UdpPid),
            {stop, Reason}
    end.


initiate_rekey(State = #{handshake := Handshake,
                               udp_pid := UdpPid,
                               remote_ip := RemoteIp,
                               remote_udp_port := RemoteUdpPort}) ->
    case vpn_handshake:begin_rekey(Handshake) of
        {send, Packet, Handshake1} ->
            case vpn_udp:send(UdpPid, RemoteIp, RemoteUdpPort, Packet) of
                ok ->
                    State1 = incr_counter(State#{handshake := Handshake1}, handshake_control_tx),
                    NextEpoch = current_key_epoch(State) + 1,
                    {reply, {ok, NextEpoch}, schedule_handshake_retry(State1, Handshake1)};
                {error, Reason} ->
                    {reply, {error, Reason}, incr_counter(State, handshake_failures)}
            end;
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end.

start_handshake(State = #{handshake := Handshake}) ->
    case vpn_handshake:begin_handshake(Handshake) of
        {established, Handshake1} ->
            {noreply, activate_session_crypto(State#{handshake := Handshake1})};
        {send, Packet, Handshake1} ->
            send_handshake(Packet, State#{handshake := Handshake1})
    end.

retry_handshake(State = #{handshake := Handshake}) ->
    case vpn_handshake:retry(Handshake) of
        {established, Handshake1} ->
            {noreply, activate_session_crypto(
                        State#{handshake := Handshake1, handshake_timer := undefined})};
        {send, Packet, Handshake1} ->
            send_handshake(Packet, State#{handshake := Handshake1, handshake_timer := undefined});
        {failed, Reason, Handshake1} ->
            logger:error("vpn_link handshake failed: ~p", [Reason]),
            {noreply, incr_counter(State#{handshake := Handshake1,
                                          handshake_timer := undefined},
                                   handshake_failures)}
    end.

handle_handshake_packet(Packet, State = #{handshake := Handshake}) ->
    State1 = incr_counter(State, handshake_control_rx),
    case vpn_handshake:handle_frame(Packet, Handshake) of
        {send, Reply, Handshake1} ->
            send_handshake(Reply, State1#{handshake := Handshake1});
        {send_established, Reply, Handshake1} ->
            send_established_handshake(Reply, State1#{handshake := Handshake1});
        {defer, Handshake1} ->
            logger:debug("vpn_link deferred handshake frame until certificate authentication completes", []),
            {noreply, State1#{handshake := Handshake1}};
        {established, Handshake1} ->
            cancel_handshake_timer(State1),
            logger:info("vpn_link handshake established with ~s",
                        [maps:get(remote_peer_id, State1)]),
            EstablishedState = activate_session_crypto(
                                 State1#{handshake := Handshake1,
                                         handshake_timer := undefined}),
            {noreply, EstablishedState};
        {reject, Reason, Handshake1} ->
            logger:warning("vpn_link rejected handshake frame: ~p", [Reason]),
            {noreply, incr_counter(State1#{handshake := Handshake1}, handshake_failures)}
    end.


send_established_handshake(Packet, State = #{udp_pid := UdpPid,
                                               remote_ip := RemoteIp,
                                               remote_udp_port := RemoteUdpPort,
                                               remote_peer_id := RemotePeerId}) ->
    case vpn_udp:send(UdpPid, RemoteIp, RemoteUdpPort, Packet) of
        ok ->
            cancel_handshake_timer(State),
            logger:info("vpn_link handshake established with ~s", [RemotePeerId]),
            EstablishedState = activate_session_crypto(State#{handshake_timer := undefined}),
            {noreply, incr_counter(EstablishedState, handshake_control_tx)};
        {error, Reason} ->
            logger:error("vpn_link failed to send final handshake frame: ~p", [Reason]),
            {noreply, incr_counter(State, handshake_failures)}
    end.

send_handshake(Packet, State = #{udp_pid := UdpPid,
                                 remote_ip := RemoteIp,
                                 remote_udp_port := RemoteUdpPort,
                                 handshake := Handshake}) ->
    case vpn_udp:send(UdpPid, RemoteIp, RemoteUdpPort, Packet) of
        ok ->
            State1 = incr_counter(State, handshake_control_tx),
            {noreply, schedule_handshake_retry(State1, Handshake)};
        {error, Reason} ->
            logger:error("vpn_link failed to send handshake frame: ~p", [Reason]),
            {noreply, incr_counter(State, handshake_failures)}
    end.

schedule_handshake_retry(State, Handshake) ->
    case vpn_handshake:established(Handshake) of
        true ->
            cancel_handshake_timer(State),
            State#{handshake_timer := undefined};
        false ->
            cancel_handshake_timer(State),
            Ref = erlang:send_after(maps:get(retry_interval, Handshake), self(), handshake_retry),
            State#{handshake_timer := Ref}
    end.

cancel_handshake_timer(State) ->
    case maps:get(handshake_timer, State, undefined) of
        undefined -> ok;
        Ref -> _ = erlang:cancel_timer(Ref), ok
    end.

handshake_established(#{crypto := Crypto}) when is_map(Crypto) -> true;
handshake_established(#{handshake := Handshake}) ->
    vpn_handshake:established(Handshake).

initial_crypto(_Psk, _PeerId, #{mode := certificate_control}) ->
    undefined;
initial_crypto(Psk, PeerId, _HandshakeOptions) ->
    vpn_crypto:new(Psk, PeerId).

activate_session_crypto(State = #{handshake := Handshake, peer_id := PeerId}) ->
    case vpn_handshake:session_keys(Handshake) of
        {ok, #{tx_key := TxKey, rx_key := RxKey}} ->
            SessionId = maps:get(session_id, Handshake),
            case SessionId =:= maps:get(crypto_session_id, State, undefined) of
                true -> State;
                false ->
                    CurrentEpoch = current_key_epoch(State),
                    KeyEpoch = CurrentEpoch + 1,
                    Lifecycle = case maps:get(session_lifecycle, State, undefined) of
                                    undefined -> vpn_session_lifecycle:new(KeyEpoch);
                                    Existing -> vpn_session_lifecycle:rekey(Existing, KeyEpoch)
                                end,
                    RekeyedState = case CurrentEpoch > 0 of
                                         true -> incr_counter(State, rekeys_completed);
                                         false -> State
                                     end,
                    install_session_crypto(RekeyedState, TxKey, RxKey, PeerId,
                                           KeyEpoch, SessionId, Lifecycle)
            end;
        {error, session_keys_not_ready} ->
            State
    end.

install_session_crypto(State, TxKey, RxKey, PeerId, KeyEpoch, SessionId, Lifecycle) ->
    CurrentCrypto = maps:get(crypto, State, undefined),
    CurrentReplay = maps:get(current_replay_window, State,
                             vpn_replay_window:new(?REPLAY_WINDOW_SIZE)),
    State1 = cancel_previous_crypto_timer(State),
    GraceMs = maps:get(previous_epoch_grace_ms, State,
                       ?DEFAULT_PREVIOUS_EPOCH_GRACE_MS),
    {PreviousCrypto, PreviousReplay, ExpiresAt, Timer, TimerToken} =
        case CurrentCrypto of
            Crypto when is_map(Crypto) ->
                Epoch = maps:get(key_epoch, Crypto, 0),
                Deadline = erlang:monotonic_time(millisecond) + GraceMs,
                Token = make_ref(),
                Ref = erlang:send_after(GraceMs, self(),
                                        {expire_previous_crypto, Epoch, Token}),
                {Crypto, CurrentReplay, Deadline, Ref, Token};
            _ ->
                {undefined, undefined, undefined, undefined, undefined}
        end,
    State1#{previous_crypto := PreviousCrypto,
            previous_replay_window := PreviousReplay,
            previous_crypto_expires_at := ExpiresAt,
            previous_crypto_timer := Timer,
            previous_crypto_timer_token := TimerToken,
            current_replay_window := vpn_replay_window:new(?REPLAY_WINDOW_SIZE),
            crypto := vpn_crypto:new_session(TxKey, RxKey, PeerId, KeyEpoch),
            crypto_session_id := SessionId,
            session_lifecycle := Lifecycle,
            tx_seq := 0,
            rx_seq := 0}.

cancel_previous_crypto_timer(State) ->
    case maps:get(previous_crypto_timer, State, undefined) of
        undefined -> State;
        Ref ->
            _ = erlang:cancel_timer(Ref),
            State#{previous_crypto_timer := undefined,
                   previous_crypto_timer_token := undefined}
    end.

replay_info(State) ->
    Current = vpn_replay_window:info(
                maps:get(current_replay_window, State,
                         vpn_replay_window:new(?REPLAY_WINDOW_SIZE))),
    Previous = case maps:get(previous_replay_window, State, undefined) of
                   Window when is_map(Window) -> vpn_replay_window:info(Window);
                   _ -> undefined
               end,
    PreviousEpoch = case maps:get(previous_crypto, State, undefined) of
                        #{key_epoch := Epoch} -> Epoch;
                        _ -> undefined
                    end,
    ExpiresIn = case maps:get(previous_crypto_expires_at, State, undefined) of
                    undefined -> undefined;
                    Deadline -> max(0, Deadline - erlang:monotonic_time(millisecond))
                end,
    #{window_size => ?REPLAY_WINDOW_SIZE,
      current_epoch => current_key_epoch(State),
      current => Current,
      previous_epoch => PreviousEpoch,
      previous => Previous,
      previous_epoch_grace_ms => maps:get(previous_epoch_grace_ms, State,
                                           ?DEFAULT_PREVIOUS_EPOCH_GRACE_MS),
      previous_epoch_expires_in_ms => ExpiresIn}.

crypto_info(#{crypto := undefined}) -> #{key_source => pending_handshake};
crypto_info(#{crypto := Crypto}) -> vpn_crypto:info(Crypto).

stop_worker(undefined, _StopFun) ->
    ok;
stop_worker(Pid, StopFun) ->
    case is_process_alive(Pid) of
        true ->
            _ = StopFun(Pid),
            ok;
        false ->
            ok
    end.

encode_and_send(Packet,
                Kind,
                Size,
                UdpPid,
                RemoteIp,
                RemoteUdpPort,
                State = #{crypto := Crypto0, tx_seq := Seq, peer_id := PeerId}) ->
    KeyEpoch = current_key_epoch(State),
    Frame = vpn_frame:encode(PeerId, KeyEpoch, Seq, Packet),
    logger:debug("vpn_frame tx seq=~p", [Seq]),
    case vpn_crypto:encode(Frame, Crypto0) of
        {ok, EncodedPacket, Crypto1} ->
            State1 = State#{crypto := Crypto1},
            State2 = incr_counter(State1, crypto_encryptions),
            send_encoded(EncodedPacket, Kind, Size, Seq, UdpPid, RemoteIp, RemoteUdpPort, State2);
        {error, Reason, Crypto1} ->
            logger:error("vpn_link failed to encode packet: ~p", [Reason]),
            {noreply, incr_counter(State#{crypto := Crypto1}, crypto_failures)};
        {error, Reason} ->
            logger:error("vpn_link failed to encode packet: ~p", [Reason]),
            {noreply, incr_counter(State, crypto_failures)}
    end.

send_encoded(EncodedPacket, Kind, Size, Seq, UdpPid, RemoteIp, RemoteUdpPort, State) ->
    case vpn_udp:send(UdpPid, RemoteIp, RemoteUdpPort, EncodedPacket) of
        ok ->
            logger:info("vpn_link udp_tx kind=~p to ~s:~p size=~p",
                        [Kind, format_ip(RemoteIp), RemoteUdpPort, Size]),
            State1 = incr_counters(State, udp_tx_packets, udp_tx_bytes, Size),
            State2 = record_session_tx(Size, State1),
            State3 = remember_debug_frame(EncodedPacket, Size, Seq, State2),
            {noreply, State3#{tx_seq := Seq + 1}};
        {error, Reason} ->
            logger:error("vpn_link failed to forward packet: ~p", [Reason]),
            {noreply, State}
    end.

decode_and_write(Packet, Mode, TunPid, State) ->
    case vpn_crypto:packet_context(Packet) of
        {ok, #{key_epoch := KeyEpoch}} ->
            decode_epoch_packet(Packet, KeyEpoch, Mode, TunPid, State);
        legacy ->
            decode_legacy_packet(Packet, Mode, TunPid, State);
        {error, Reason} ->
            logger:error("vpn_link failed to inspect encrypted packet: ~p", [Reason]),
            {noreply, incr_counter(State, crypto_failures)}
    end.

decode_epoch_packet(Packet, KeyEpoch, Mode, TunPid, State) ->
    case crypto_for_epoch(KeyEpoch, State) of
        {ok, current, Crypto} ->
            decode_with_crypto(Packet, current, crypto, Crypto, Mode, TunPid, State);
        {ok, previous, Crypto} ->
            decode_with_crypto(Packet, previous, previous_crypto, Crypto, Mode, TunPid, State);
        {error, stale_epoch} ->
            logger:warning("vpn_link rejected stale key epoch ~p before decrypt", [KeyEpoch]),
            {noreply, incr_counter(
                        incr_counter(State, stale_epoch_drops), frames_rejected)}
    end.

decode_with_crypto(Packet, CryptoSlot, StateKey, Crypto0, Mode, TunPid, State) ->
    case vpn_crypto:decode(Packet, Crypto0) of
        {ok, DecodedFrame, Crypto1} ->
            State1 = incr_counter(State#{StateKey := Crypto1}, crypto_decryptions),
            decode_frame_and_write(DecodedFrame, CryptoSlot, Mode, TunPid, State1);
        {error, Reason, Crypto1} ->
            logger:error("vpn_link failed to decode packet: ~p", [Reason]),
            {noreply, incr_counter(State#{StateKey := Crypto1}, crypto_failures)};
        {error, Reason} ->
            logger:error("vpn_link failed to decode packet: ~p", [Reason]),
            {noreply, incr_counter(State, crypto_failures)}
    end.

decode_legacy_packet(Packet, Mode, TunPid, State = #{crypto := Crypto0}) ->
    case vpn_crypto:decode(Packet, Crypto0) of
        {ok, DecodedFrame, Crypto1} ->
            State1 = State#{crypto := Crypto1},
            State2 = incr_counter(State1, crypto_decryptions),
            decode_frame_and_write(DecodedFrame, current, Mode, TunPid, State2);
        {error, _Reason, Crypto1} ->
            decode_legacy_with_previous(Packet, Mode, TunPid, State#{crypto := Crypto1});
        {error, _Reason} ->
            decode_legacy_with_previous(Packet, Mode, TunPid, State)
    end.

decode_legacy_with_previous(Packet, Mode, TunPid,
                            State = #{previous_crypto := Previous}) when is_map(Previous) ->
    decode_with_crypto(Packet, previous, previous_crypto, Previous, Mode, TunPid, State);
decode_legacy_with_previous(_Packet, _Mode, _TunPid, State) ->
    logger:error("vpn_link failed to decode packet: authentication_failed", []),
    {noreply, incr_counter(State, crypto_failures)}.

crypto_for_epoch(KeyEpoch, State) ->
    CurrentEpoch = current_key_epoch(State),
    case KeyEpoch =:= CurrentEpoch of
        true ->
            {ok, current, maps:get(crypto, State)};
        false ->
            case maps:get(previous_crypto, State, undefined) of
                #{key_epoch := KeyEpoch} = Previous ->
                    case previous_epoch_active(State) of
                        true -> {ok, previous, Previous};
                        false -> {error, stale_epoch}
                    end;
                _ ->
                    {error, stale_epoch}
            end
    end.

decode_frame_and_write(DecodedFrame, CryptoSlot, Mode, TunPid, State) ->
    case vpn_frame:decode(DecodedFrame) of
        {ok, #{key_epoch := KeyEpoch, seq := Seq,
               peer_id := PeerId, payload := DecodedPacket}} ->
            logger:debug("vpn_frame rx epoch=~p seq=~p peer_id=~p",
                         [KeyEpoch, Seq, PeerId]),
            validate_and_write(KeyEpoch, PeerId, Seq, DecodedPacket,
                               CryptoSlot, Mode, TunPid, State);
        {error, Reason} ->
            logger:error("vpn_link failed to decode frame: ~p", [Reason]),
            {noreply, State}
    end.

validate_and_write(KeyEpoch, PeerId, Seq, DecodedPacket, CryptoSlot, Mode, TunPid, State) ->
    case {validate_frame_epoch(KeyEpoch, CryptoSlot, State),
          validate_frame_peer_id(PeerId, maps:get(remote_peer_id, State))} of
        {{ok, EpochKind}, ok} ->
            case check_replay(EpochKind, Seq, State) of
                {ok, State1} ->
                    Size = byte_size(DecodedPacket),
                    State2 = incr_counter(State1#{rx_seq := Seq}, frames_accepted),
                    State3 = record_epoch_rx(EpochKind, Size, State2),
                    State4 = case EpochKind of
                                 previous -> incr_counter(State3, previous_epoch_accepted);
                                 current -> State3
                             end,
                    Kind = packet_kind(DecodedPacket, Mode),
                    write_decoded(DecodedPacket, Kind, Size, TunPid, State4);
                {error, duplicate, State1} ->
                    logger:warning("vpn_link rejected duplicate frame epoch=~p seq=~p",
                                   [KeyEpoch, Seq]),
                    {noreply, incr_counter(
                                incr_counter(
                                  incr_counter(State1, duplicate_frames), replay_drops),
                                frames_rejected)};
                {error, too_old, State1} ->
                    logger:warning("vpn_link rejected stale sequence epoch=~p seq=~p",
                                   [KeyEpoch, Seq]),
                    {noreply, incr_counter(
                                incr_counter(State1, replay_drops),
                                frames_rejected)}
            end;
        {{error, {key_epoch_mismatch, ExpectedEpoch, ReceivedEpoch}}, _} ->
            logger:warning("vpn_link rejected frame: expected key epoch ~p received ~p",
                           [ExpectedEpoch, ReceivedEpoch]),
            {noreply, incr_counter(
                        incr_counter(State, stale_epoch_drops), frames_rejected)};
        {{error, previous_epoch_expired}, _} ->
            logger:warning("vpn_link rejected expired previous key epoch ~p", [KeyEpoch]),
            {noreply, incr_counter(
                        incr_counter(State, stale_epoch_drops), frames_rejected)};
        {{ok, _}, {error, {peer_id_mismatch, Expected, Received}}} ->
            logger:warning("vpn_link rejected frame: expected ~s received ~s",
                           [Expected, Received]),
            {noreply, incr_counter(State, frames_rejected)}
    end.

write_decoded(DecodedPacket, Kind, Size, TunPid, State) ->
    case vpn_tun:write(TunPid, DecodedPacket) of
        ok ->
            logger:info("vpn_link tun_tx kind=~p size=~p", [Kind, Size]),
            State1 = incr_counters(State, tun_tx_packets, tun_tx_bytes, Size),
            {noreply, State1};
        {error, Reason} ->
            logger:error("vpn_link failed to write UDP packet to TUN: ~p",
                         [Reason]),
            {noreply, State}
    end.

stats_map(State = #{tun_pid := TunPid,
                    udp_pid := UdpPid,
                    remote_ip := RemoteIp,
                    remote_udp_port := RemoteUdpPort}) ->
    Handshake = maps:get(handshake, State),
    maps:merge(#{tun_pid => TunPid,
                 udp_pid => UdpPid,
                 remote_ip => RemoteIp,
                 remote_port => RemoteUdpPort,
                 handshake => vpn_handshake:info(Handshake),
                 crypto => crypto_info(State),
                 session => session_info(State),
                 replay => replay_info(State),
                 debug_replay => debug_replay_info(State)},
               maps:with(counter_keys(), State)).

current_key_epoch(#{session_lifecycle := Lifecycle}) when is_map(Lifecycle) ->
    maps:get(key_epoch, Lifecycle);
current_key_epoch(_State) ->
    0.

validate_frame_epoch(KeyEpoch, current, State) ->
    Expected = current_key_epoch(State),
    case KeyEpoch =:= Expected of
        true -> {ok, current};
        false -> {error, {key_epoch_mismatch, Expected, KeyEpoch}}
    end;
validate_frame_epoch(KeyEpoch, previous, State) ->
    case maps:get(previous_crypto, State, undefined) of
        #{key_epoch := KeyEpoch} ->
            case previous_epoch_active(State) of
                true -> {ok, previous};
                false -> {error, previous_epoch_expired}
            end;
        _ ->
            {error, {key_epoch_mismatch, current_key_epoch(State), KeyEpoch}}
    end.

check_replay(current, Seq, State = #{current_replay_window := Window}) ->
    case vpn_replay_window:check(Seq, Window) of
        {ok, Window1} -> {ok, State#{current_replay_window := Window1}};
        {error, Reason, Window1} ->
            {error, Reason, State#{current_replay_window := Window1}}
    end;
check_replay(previous, Seq, State = #{previous_replay_window := Window}) when is_map(Window) ->
    case vpn_replay_window:check(Seq, Window) of
        {ok, Window1} -> {ok, State#{previous_replay_window := Window1}};
        {error, Reason, Window1} ->
            {error, Reason, State#{previous_replay_window := Window1}}
    end.

record_epoch_rx(current, Size, State) -> record_session_rx(Size, State);
record_epoch_rx(previous, _Size, State) -> State.

previous_epoch_active(State) ->
    case maps:get(previous_crypto_expires_at, State, undefined) of
        undefined -> false;
        Deadline -> erlang:monotonic_time(millisecond) =< Deadline
    end.

record_session_tx(_Size, State = #{session_lifecycle := undefined}) ->
    State;
record_session_tx(Size, State = #{session_lifecycle := Lifecycle}) ->
    State#{session_lifecycle := vpn_session_lifecycle:record_tx(Size, Lifecycle)}.

record_session_rx(_Size, State = #{session_lifecycle := undefined}) ->
    State;
record_session_rx(Size, State = #{session_lifecycle := Lifecycle}) ->
    State#{session_lifecycle := vpn_session_lifecycle:record_rx(Size, Lifecycle)}.

session_info(#{session_lifecycle := undefined}) ->
    undefined;
session_info(#{session_lifecycle := Lifecycle}) ->
    vpn_session_lifecycle:info(Lifecycle).

zero_counters() ->
    maps:from_list([{Key, 0} || Key <- counter_keys()]).

counter_keys() ->
    [tun_rx_packets,
     tun_rx_bytes,
     udp_tx_packets,
     udp_tx_bytes,
     udp_rx_packets,
     udp_rx_bytes,
     tun_tx_packets,
     tun_tx_bytes,
     frames_accepted,
     frames_rejected,
     crypto_encryptions,
     crypto_decryptions,
     crypto_failures,
     handshake_control_tx,
     handshake_control_rx,
     handshake_failures,
     handshake_blocked_packets,
     rekeys_completed,
     replay_drops,
     duplicate_frames,
     stale_epoch_drops,
     previous_epoch_accepted,
     debug_replayed_frames].

reset_counter_values(State) ->
    maps:merge(State, zero_counters()).

incr_counters(State, PacketKey, ByteKey, Size) ->
    State#{PacketKey := maps:get(PacketKey, State) + 1,
           ByteKey := maps:get(ByteKey, State) + Size}.

incr_counter(State, Key) ->
    State#{Key := maps:get(Key, State) + 1}.

validate_frame_peer_id(FramePeerId, ExpectedPeerId) ->
    Received = normalize_peer_id(FramePeerId),
    Expected = normalize_peer_id(ExpectedPeerId),
    case Received =:= Expected of
        true ->
            ok;
        false ->
            {error, {peer_id_mismatch, Expected, Received}}
    end.

normalize_peer_id(PeerId) when is_binary(PeerId) ->
    PeerId;
normalize_peer_id(PeerId) when is_atom(PeerId) ->
    atom_to_binary(PeerId, utf8).

debug_replay_info(State) ->
    Enabled = maps:get(debug_replay_enabled, State, false),
    History = maps:get(debug_frame_history, State, []),
    #{enabled => Enabled,
      retained_frames => length(History),
      history_limit => ?DEBUG_FRAME_HISTORY_LIMIT,
      replayed_frames => maps:get(debug_replayed_frames, State, 0)}.

debug_frame_history_info(State) ->
    [maps:without([packet], Entry)
     || Entry <- lists:reverse(maps:get(debug_frame_history, State, []))].

remember_debug_frame(_Packet, _Size, _Seq,
                     State = #{debug_replay_enabled := false}) ->
    State;
remember_debug_frame(Packet, Size, Seq, State) ->
    Entry = #{key_epoch => current_key_epoch(State),
              seq => Seq,
              plaintext_size => Size,
              encrypted_size => byte_size(Packet),
              packet => Packet},
    History0 = [Entry | maps:get(debug_frame_history, State, [])],
    History1 = lists:sublist(History0, ?DEBUG_FRAME_HISTORY_LIMIT),
    State#{debug_frame_history := History1}.

replay_debug_frame(_KeyEpoch, _Seq,
                   State = #{debug_replay_enabled := false}) ->
    {reply, {error, debug_replay_disabled}, State};
replay_debug_frame(KeyEpoch, Seq,
                   State = #{udp_pid := UdpPid,
                             remote_ip := RemoteIp,
                             remote_udp_port := RemoteUdpPort})
  when is_integer(KeyEpoch), KeyEpoch >= 0,
       is_integer(Seq), Seq >= 0 ->
    case find_debug_frame(KeyEpoch, Seq,
                          maps:get(debug_frame_history, State, [])) of
        {ok, #{packet := Packet}} ->
            case vpn_udp:send(UdpPid, RemoteIp, RemoteUdpPort, Packet) of
                ok ->
                    logger:warning("vpn_link replayed debug frame epoch=~p seq=~p",
                                   [KeyEpoch, Seq]),
                    {reply, ok, incr_counter(State, debug_replayed_frames)};
                {error, Reason} ->
                    {reply, {error, Reason}, State}
            end;
        error ->
            {reply, {error, frame_not_retained}, State}
    end;
replay_debug_frame(_KeyEpoch, _Seq, State) ->
    {reply, {error, invalid_frame_selector}, State}.


send_debug_frames(_Count, State = #{debug_replay_enabled := false}) ->
    {reply, {error, debug_replay_disabled}, State};
send_debug_frames(Count, State)
  when is_integer(Count), Count > 0, Count =< ?DEBUG_FRAME_HISTORY_LIMIT ->
    case handshake_established(State) of
        true ->
            StartSeq = maps:get(tx_seq, State),
            case send_debug_frames_loop(Count, 0, State) of
                {ok, State1} ->
                    EndSeq = maps:get(tx_seq, State1) - 1,
                    logger:warning(
                      "vpn_link sent ~p debug dataplane frames epoch=~p seq=~p..~p",
                      [Count, current_key_epoch(State1), StartSeq, EndSeq]),
                    {reply, {ok, #{sent => Count,
                                   key_epoch => current_key_epoch(State1),
                                   first_seq => StartSeq,
                                   last_seq => EndSeq}},
                     State1};
                {error, Reason, State1} ->
                    {reply, {error, Reason}, State1}
            end;
        false ->
            {reply, {error, handshake_not_established}, State}
    end;
send_debug_frames(_Count, State) ->
    {reply, {error, invalid_frame_count}, State}.

send_debug_frames_loop(Count, Count, State) ->
    {ok, State};
send_debug_frames_loop(Count, Index,
                       State = #{udp_pid := UdpPid,
                                 remote_ip := RemoteIp,
                                 remote_udp_port := RemoteUdpPort}) ->
    Packet = debug_payload(Index),
    Size = byte_size(Packet),
    #{tx_seq := TxSeq} = State,
    case encode_and_send(Packet, debug, Size, UdpPid, RemoteIp, RemoteUdpPort, #{tx_seq := TxSeq} = State) of
        {noreply, State1 = #{tx_seq := TxSeq2}} when TxSeq2 > TxSeq ->
            send_debug_frames_loop(Count, Index + 1, State1);
        {noreply, State1} ->
            {error, send_failed, State1}
    end.

debug_payload(Index) ->
    <<16#45, 0, 0, 48,
      Index:32/unsigned-big,
      0:320>>.

find_debug_frame(_KeyEpoch, _Seq, []) ->
    error;
find_debug_frame(KeyEpoch, Seq,
                 [#{key_epoch := KeyEpoch, seq := Seq} = Entry | _]) ->
    {ok, Entry};
find_debug_frame(KeyEpoch, Seq, [_ | Rest]) ->
    find_debug_frame(KeyEpoch, Seq, Rest).

packet_kind(Packet, tap) ->
    ethernet_packet_kind(Packet);

packet_kind(Packet, tun) ->
    ip_packet_kind(Packet).

ethernet_packet_kind(Packet) when byte_size(Packet) >= 14 ->
    case Packet of
        <<_:12/binary, 16#0806:16/big, _/binary>> ->
            arp;
        <<_:12/binary, 16#0800:16/big, Ipv4/binary>> ->
            ipv4_packet_kind(Ipv4);
        <<_:12/binary, 16#86DD:16/big, _/binary>> ->
            ipv6;
        _ ->
            unknown
    end;
ethernet_packet_kind(_Packet) ->
    unknown.

ip_packet_kind(<<4:4, _/bitstring>> = Packet) ->
    ipv4_packet_kind(Packet);
ip_packet_kind(<<6:4, _/bitstring>>) ->
    ipv6;
ip_packet_kind(_Packet) ->
    unknown.

ipv4_packet_kind(<<FirstByte, _:8/binary, Protocol, Rest/binary>>) ->
    HeaderLen = (FirstByte band 16#0F) * 4,
    HasIcmpType = HeaderLen >= 20 andalso byte_size(Rest) >= HeaderLen - 9,
    case {Protocol, HasIcmpType} of
        {1, true} ->
            IcmpOffset = HeaderLen - 10,
            case Rest of
                <<_:IcmpOffset/binary, 8, _/binary>> ->
                    ipv4_icmp_echo_request;
                <<_:IcmpOffset/binary, 0, _/binary>> ->
                    ipv4_icmp_echo_reply;
                _ ->
                    ipv4_other
            end;
        {17, _} ->
            ipv4_udp;
        _ ->
            ipv4_other
    end;
ipv4_packet_kind(_Packet) ->
    ipv4_other.

format_ip({A, B, C, D}) ->
    io_lib:format("~B.~B.~B.~B", [A, B, C, D]);
format_ip(Ip) ->
    io_lib:format("~p", [Ip]).
