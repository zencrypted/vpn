%%%-------------------------------------------------------------------
%% @doc UDP sink worker for local test traffic.
%%%-------------------------------------------------------------------
-module(vpn_udp_sink).

-behaviour(gen_server).

-export([start_link/1, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

start_link(Port) ->
    gen_server:start_link(?MODULE, Port, []).

stop(Pid) ->
    gen_server:stop(Pid).

init(Port) ->
    process_flag(trap_exit, true),
    case vpn_udp:start_link(Port, self()) of
        {ok, UdpPid} ->
            {ok, #{udp_pid => UdpPid, port => Port}};
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({vpn_udp_packet, UdpPid, Ip, Port, Packet},
            State = #{udp_pid := UdpPid}) ->
    logger:info("vpn_udp_sink received packet from ~p:~p: ~p bytes, first16=~p",
                [Ip, Port, byte_size(Packet), first16(Packet)]),
    {noreply, State};
handle_info({vpn_udp_packet, _OtherUdpPid, _Ip, _Port, _Packet}, State) ->
    {noreply, State};
handle_info({'EXIT', UdpPid, Reason}, State = #{udp_pid := UdpPid}) ->
    {stop, {udp_exit, Reason}, State};
handle_info(_Message, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    stop_udp(maps:get(udp_pid, State, undefined)),
    ok.

first16(Packet) when byte_size(Packet) =< 16 ->
    binary:encode_hex(Packet);
first16(Packet) ->
    binary:encode_hex(binary:part(Packet, 0, 16)).

stop_udp(undefined) ->
    ok;
stop_udp(UdpPid) ->
    case is_process_alive(UdpPid) of
        true ->
            _ = vpn_udp:stop(UdpPid),
            ok;
        false ->
            ok
    end.
