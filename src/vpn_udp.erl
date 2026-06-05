%%%-------------------------------------------------------------------
%% @doc Minimal UDP worker.
%%%-------------------------------------------------------------------
-module(vpn_udp).

-behaviour(gen_server).

-export([start_link/1, stop/1, send/4]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

start_link(Port) ->
    gen_server:start_link(?MODULE, Port, []).

stop(Pid) ->
    gen_server:stop(Pid).

send(Pid, Host, Port, Packet) when is_binary(Packet) ->
    gen_server:call(Pid, {send, Host, Port, Packet}).

init(Port) ->
    case gen_udp:open(Port, [binary, {active, true}]) of
        {ok, Socket} ->
            {ok, #{socket => Socket, port => Port}};
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call({send, Host, Port, Packet}, _From, State = #{socket := Socket}) ->
    Reply = gen_udp:send(Socket, Host, Port, Packet),
    {reply, Reply, State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({udp, Socket, Ip, Port, Packet}, State = #{socket := Socket}) ->
    logger:info("vpn_udp received packet from ~p:~p: ~p bytes",
                [Ip, Port, byte_size(Packet)]),
    {noreply, State};
handle_info({udp, _OtherSocket, _Ip, _Port, _Packet}, State) ->
    {noreply, State};
handle_info(_Message, State) ->
    {noreply, State}.

terminate(_Reason, #{socket := Socket}) ->
    gen_udp:close(Socket),
    ok;
terminate(_Reason, _State) ->
    ok.
