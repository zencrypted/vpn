%%%-------------------------------------------------------------------
%% @doc Bidirectional TUN to UDP link.
%%%-------------------------------------------------------------------
-module(vpn_link).

-behaviour(gen_server).

-export([start_link/5, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

start_link(TunName, TunIp, LocalUdpPort, RemoteIp, RemoteUdpPort) ->
    Args = {TunName, TunIp, LocalUdpPort, RemoteIp, RemoteUdpPort},
    gen_server:start_link(?MODULE, Args, []).

stop(Pid) ->
    gen_server:stop(Pid).

init({TunName, TunIp, LocalUdpPort, RemoteIp, RemoteUdpPort}) ->
    process_flag(trap_exit, true),
    case vpn_udp:start_link(LocalUdpPort, self()) of
        {ok, UdpPid} ->
            init_tun(UdpPid, TunName, TunIp, RemoteIp, RemoteUdpPort);
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({vpn_tun_packet, TunPid, Packet},
            State = #{tun_pid := TunPid,
                      udp_pid := UdpPid,
                      remote_ip := RemoteIp,
                      remote_udp_port := RemoteUdpPort}) ->
    case vpn_udp:send(UdpPid, RemoteIp, RemoteUdpPort, Packet) of
        ok ->
            logger:info("vpn_link forwarded packet to ~p:~p: ~p bytes",
                        [RemoteIp, RemoteUdpPort, byte_size(Packet)]),
            {noreply, State};
        {error, Reason} ->
            logger:error("vpn_link failed to forward packet: ~p", [Reason]),
            {noreply, State}
    end;
handle_info({vpn_tun_packet, _OtherTunPid, _Packet}, State) ->
    {noreply, State};
handle_info({vpn_udp_packet, UdpPid, Ip, Port, Packet},
            State = #{udp_pid := UdpPid, tun_pid := TunPid}) ->
    case vpn_tun:write(TunPid, Packet) of
        ok ->
            logger:info("vpn_link wrote UDP packet from ~p:~p to TUN: ~p bytes",
                        [Ip, Port, byte_size(Packet)]),
            {noreply, State};
        {error, Reason} ->
            logger:error("vpn_link failed to write UDP packet to TUN: ~p",
                         [Reason]),
            {noreply, State}
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
            {ok, #{udp_pid => UdpPid,
                   tun_pid => TunPid,
                   remote_ip => RemoteIp,
                   remote_udp_port => RemoteUdpPort}};
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
