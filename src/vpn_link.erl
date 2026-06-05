%%%-------------------------------------------------------------------
%% @doc Bidirectional TUN to UDP link.
%%%-------------------------------------------------------------------
-module(vpn_link).

-behaviour(gen_server).

-export([start_link/5, stop/1, stats/1, reset_stats/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

start_link(TunName, TunIp, LocalUdpPort, RemoteIp, RemoteUdpPort) ->
    Args = {TunName, TunIp, LocalUdpPort, RemoteIp, RemoteUdpPort},
    gen_server:start_link(?MODULE, Args, []).

stop(Pid) ->
    gen_server:stop(Pid).

stats(Pid) ->
    gen_server:call(Pid, stats).

reset_stats(Pid) ->
    gen_server:call(Pid, reset_stats).

init({TunName, TunIp, LocalUdpPort, RemoteIp, RemoteUdpPort}) ->
    process_flag(trap_exit, true),
    case vpn_udp:start_link(LocalUdpPort, self()) of
        {ok, UdpPid} ->
            init_tun(UdpPid, TunName, TunIp, RemoteIp, RemoteUdpPort);
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

handle_info({vpn_tun_packet, TunPid, Packet},
            State = #{tun_pid := TunPid,
                      udp_pid := UdpPid,
                      remote_ip := RemoteIp,
                      remote_udp_port := RemoteUdpPort}) ->
    Kind = packet_kind(Packet),
    Size = byte_size(Packet),
    logger:info("vpn_link tun_rx kind=~p size=~p", [Kind, Size]),
    State1 = incr_counters(State, tun_rx_packets, tun_rx_bytes, Size),
    case vpn_udp:send(UdpPid, RemoteIp, RemoteUdpPort, Packet) of
        ok ->
            logger:info("vpn_link udp_tx kind=~p to ~s:~p size=~p",
                        [Kind, format_ip(RemoteIp), RemoteUdpPort, Size]),
            State2 = incr_counters(State1, udp_tx_packets, udp_tx_bytes, Size),
            {noreply, State2};
        {error, Reason} ->
            logger:error("vpn_link failed to forward packet: ~p", [Reason]),
            {noreply, State1}
    end;
handle_info({vpn_tun_packet, _OtherTunPid, _Packet}, State) ->
    {noreply, State};
handle_info({vpn_udp_packet, UdpPid, Ip, Port, Packet},
            State = #{udp_pid := UdpPid, tun_pid := TunPid}) ->
    Kind = packet_kind(Packet),
    Size = byte_size(Packet),
    logger:info("vpn_link udp_rx kind=~p from ~s:~p size=~p",
                [Kind, format_ip(Ip), Port, Size]),
    State1 = incr_counters(State, udp_rx_packets, udp_rx_bytes, Size),
    case vpn_tun:write(TunPid, Packet) of
        ok ->
            logger:info("vpn_link tun_tx kind=~p size=~p", [Kind, Size]),
            State2 = incr_counters(State1, tun_tx_packets, tun_tx_bytes, Size),
            {noreply, State2};
        {error, Reason} ->
            logger:error("vpn_link failed to write UDP packet to TUN: ~p",
                         [Reason]),
            {noreply, State1}
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

init_tun(UdpPid, TunName, TunIp, RemoteIp, RemoteUdpPort) ->
    case vpn_tun:start_link(TunName, TunIp, self()) of
        {ok, TunPid} ->
            {ok, maps:merge(#{udp_pid => UdpPid,
                              tun_pid => TunPid,
                              remote_ip => RemoteIp,
                              remote_udp_port => RemoteUdpPort},
                            zero_counters())};
        {error, Reason} ->
            _ = vpn_udp:stop(UdpPid),
            {stop, Reason}
    end.

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

stats_map(State = #{tun_pid := TunPid,
                    udp_pid := UdpPid,
                    remote_ip := RemoteIp,
                    remote_udp_port := RemoteUdpPort}) ->
    maps:merge(#{tun_pid => TunPid,
                 udp_pid => UdpPid,
                 remote_ip => RemoteIp,
                 remote_port => RemoteUdpPort},
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
     tun_tx_bytes].

reset_counter_values(State) ->
    maps:merge(State, zero_counters()).

incr_counters(State, PacketKey, ByteKey, Size) ->
    State#{PacketKey := maps:get(PacketKey, State) + 1,
           ByteKey := maps:get(ByteKey, State) + Size}.

packet_kind(Packet) when byte_size(Packet) >= 14 ->
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
packet_kind(_Packet) ->
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
