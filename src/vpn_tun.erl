%%%-------------------------------------------------------------------
%% @doc Thin TUN/TAP wrapper around tuncer.
%%%-------------------------------------------------------------------
-module(vpn_tun).

-behaviour(gen_server).

-export([open/2, close/1, devname/1]).
-export([start_link/2, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

open(Name, Ip) ->
    case tuncer:create(Name, [tap, no_pi, {active, true}]) of
        {ok, Ref} ->
            up_or_destroy(Ref, Ip);
        {error, Reason} ->
            {error, Reason}
    end.

close(Ref) ->
    tuncer:destroy(Ref).

devname(Ref) ->
    tuncer:devname(Ref).

start_link(Name, Ip) ->
    gen_server:start_link(?MODULE, {Name, Ip}, []).

stop(Pid) ->
    gen_server:stop(Pid).

init({Name, Ip}) ->
    case open(Name, Ip) of
        {ok, Ref} ->
            {ok, #{ref => Ref, name => Name, ip => Ip}};
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({tuntap, Ref, Packet}, State = #{ref := Ref}) ->
    logger:info("vpn_tun received packet: ~p bytes", [byte_size(Packet)]),
    {noreply, State};
handle_info({tuntap, _OtherRef, _Packet}, State) ->
    {noreply, State};
handle_info(_Message, State) ->
    {noreply, State}.

terminate(_Reason, #{ref := Ref}) ->
    _ = close(Ref),
    ok;
terminate(_Reason, _State) ->
    ok.

up_or_destroy(Ref, Ip) ->
    case tuncer:up(Ref, Ip) of
        ok ->
            {ok, Ref};
        {error, Reason} ->
            _ = tuncer:destroy(Ref),
            {error, Reason}
    end.
