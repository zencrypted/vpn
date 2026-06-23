%%%-------------------------------------------------------------------
%% @doc Bidirectional TUN to UDP link.
%%%-------------------------------------------------------------------
-module(vpn_link).

-behaviour(gen_server).

-export([start_link/5, start_link/6, start_link/8, start_link/9, start_link/10, stop/1, stats/1, reset_stats/1]).
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
                                 handshake => Handshake,
                                 handshake_timer => undefined,
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

handshake_established(#{handshake := Handshake}) ->
    vpn_handshake:established(Handshake).

initial_crypto(_Psk, _PeerId, #{mode := certificate_control}) ->
    undefined;
initial_crypto(Psk, PeerId, _HandshakeOptions) ->
    vpn_crypto:new(Psk, PeerId).

activate_session_crypto(State = #{handshake := Handshake, peer_id := PeerId}) ->
    case vpn_handshake:session_keys(Handshake) of
        {ok, #{tx_key := TxKey, rx_key := RxKey}} ->
            State#{crypto := vpn_crypto:new_session(TxKey, RxKey, PeerId)};
        {error, session_keys_not_ready} ->
            State
    end.

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
    Frame = vpn_frame:encode(PeerId, Seq, Packet),
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
            {noreply, State1#{tx_seq := Seq + 1}};
        {error, Reason} ->
            logger:error("vpn_link failed to forward packet: ~p", [Reason]),
            {noreply, State}
    end.

decode_and_write(Packet, Mode, TunPid, State = #{crypto := Crypto0}) ->
    case vpn_crypto:decode(Packet, Crypto0) of
        {ok, DecodedFrame, Crypto1} ->
            State1 = State#{crypto := Crypto1},
            State2 = incr_counter(State1, crypto_decryptions),
            decode_frame_and_write(DecodedFrame, Mode, TunPid, State2);
        {error, Reason, Crypto1} ->
            logger:error("vpn_link failed to decode packet: ~p", [Reason]),
            {noreply, incr_counter(State#{crypto := Crypto1}, crypto_failures)};
        {error, Reason} ->
            logger:error("vpn_link failed to decode packet: ~p", [Reason]),
            {noreply, incr_counter(State, crypto_failures)}
    end.

decode_frame_and_write(DecodedFrame, Mode, TunPid, State) ->
    case vpn_frame:decode(DecodedFrame) of
        {ok, #{seq := Seq, peer_id := PeerId, payload := DecodedPacket}} ->
            logger:debug("vpn_frame rx seq=~p peer_id=~p", [Seq, PeerId]),
            validate_and_write(PeerId, Seq, DecodedPacket, Mode, TunPid, State);
        {error, Reason} ->
            logger:error("vpn_link failed to decode frame: ~p", [Reason]),
            {noreply, State}
    end.

validate_and_write(PeerId, Seq, DecodedPacket, Mode, TunPid, State) ->
    case validate_frame_peer_id(PeerId, maps:get(remote_peer_id, State)) of
        ok ->
            State1 = incr_counter(State#{rx_seq := Seq}, frames_accepted),
            Kind = packet_kind(DecodedPacket, Mode),
            Size = byte_size(DecodedPacket),
            write_decoded(DecodedPacket, Kind, Size, TunPid, State1);
        {error, {peer_id_mismatch, Expected, Received}} ->
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
                 crypto => crypto_info(State)},
               maps:with(counter_keys(), State)).

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
     handshake_blocked_packets].

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
