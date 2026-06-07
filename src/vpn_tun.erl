%%%-------------------------------------------------------------------
%% @doc Thin TUN/TAP wrapper around tuncer.
%%%-------------------------------------------------------------------
-module(vpn_tun).

-behaviour(gen_server).

-export([open/2, open/3, close/1, devname/1, write/2]).
-export([start_link/2, start_link/3, start_link/4, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

open(Name, Ip) ->
    open(Name, Ip, tap).

open(Name, Ip, Mode) ->
    case tuncer:create(Name, tun_options(Mode)) of
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
    start_link(Name, Ip, undefined).

start_link(Name, Ip, OwnerPid) ->
    start_link(Name, Ip, OwnerPid, tap).

start_link(Name, Ip, OwnerPid, Mode) ->
    gen_server:start_link(?MODULE, {Name, Ip, OwnerPid, Mode}, []).

stop(Pid) ->
    gen_server:stop(Pid).

write(Pid, Packet) when is_binary(Packet) ->
    gen_server:call(Pid, {write, Packet}).

init({Name, Ip, OwnerPid, Mode}) ->
    case open(Name, Ip, Mode) of
        {ok, Ref} ->
            Fd = tuncer:getfd(Ref),
            {ok, #{ref => Ref,
                   fd => Fd,
                   name => Name,
                   ip => Ip,
                   mode => Mode,
                   owner => OwnerPid,
                   mock => false}};
        {error, Reason} ->
            logger:warning("Failed to open TUN/TAP device ~s (~p): ~p. Falling back to mock/dummy mode.", [Name, Mode, Reason]),
            {ok, #{ref => undefined,
                   fd => undefined,
                   name => Name,
                   ip => Ip,
                   mode => Mode,
                   owner => OwnerPid,
                   mock => true}}
    end.

handle_call({write, _Packet}, _From, State = #{mock := true}) ->
    {reply, ok, State};
handle_call({write, Packet}, _From, State = #{fd := Fd}) ->
    {reply, normalize_write_reply(tuncer:write(Fd, Packet)), State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({tuntap, Ref, Packet}, State = #{ref := Ref}) ->
    logger:info("vpn_tun received packet: ~p bytes", [byte_size(Packet)]),
    maybe_send_packet(Packet, State),
    {noreply, State};
handle_info({tuntap, _OtherRef, _Packet}, State) ->
    {noreply, State};
handle_info(_Message, State) ->
    {noreply, State}.

terminate(_Reason, #{ref := Ref, mock := false}) ->
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

maybe_send_packet(_Packet, #{owner := undefined}) ->
    ok;
maybe_send_packet(Packet, #{owner := OwnerPid}) ->
    OwnerPid ! {vpn_tun_packet, self(), Packet},
    ok.

normalize_write_reply(ok) ->
    ok;
normalize_write_reply({error, Reason}) ->
    {error, Reason};
normalize_write_reply({ok, Size}) ->
    {error, {partial_write, Size}}.

tun_options(tap) ->
    [tap, no_pi, {active, true}];
tun_options(tun) ->
    [tun, no_pi, {active, true}].
