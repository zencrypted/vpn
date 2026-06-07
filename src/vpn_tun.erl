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
    case os:type() of
        {unix, darwin} ->
            open_utun(Name, Ip);
        {unix, linux} ->
            case tuncer:create(Name, tun_options(Mode)) of
                {ok, Ref} ->
                    up_or_destroy(Ref, Ip);
                {error, Reason} ->
                    {error, Reason}
            end;
        Other ->
            logger:warning("Unsupported OS ~p, attempting fallback with tuncer", [Other]),
            case tuncer:create(Name, tun_options(Mode)) of
                {ok, Ref} ->
                    up_or_destroy(Ref, Ip);
                {error, Reason} ->
                    {error, Reason}
            end
    end.

close({utun_port, Port}) ->
    catch erlang:port_close(Port),
    ok;
close(Ref) ->
    tuncer:destroy(Ref).

devname({utun_port, _Port, _Socket, Name}) ->
    Name;
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
        {ok, {utun_port, Port, Socket, ActualName}} ->
            {ok, #{ref => {utun_port, Port},
                   fd => Socket,
                   name => ActualName,
                   ip => Ip,
                   mode => Mode,
                   owner => OwnerPid,
                   mock => false}};
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
handle_call({write, Packet}, _From, State = #{fd := Fd, ref := {utun_port, _}}) ->
    Header = family_header(Packet),
    Payload = <<Header/binary, Packet/binary>>,
    {reply, normalize_write_reply(tuncer:write(Fd, Payload)), State};
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
handle_info({Port, {data, Data}}, State = #{ref := {utun_port, Port}}) ->
    case Data of
        <<_Family:32/big, IpPacket/binary>> ->
            logger:info("vpn_tun received packet (utun): ~p bytes", [byte_size(IpPacket)]),
            maybe_send_packet(IpPacket, State);
        _ ->
            logger:warning("vpn_tun received invalid/short packet (utun): ~p bytes", [byte_size(Data)])
    end,
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

open_utun(Name, Ip) ->
    StartUnit = parse_unit(Name),
    open_utun_try(StartUnit, Name, Ip).

open_utun_try(Unit, Name, Ip) ->
    case procket:socket(32, 2, 2) of
        {ok, Socket} ->
            NameBin = <<"com.apple.net.utun_control">>,
            Padding = 96 - byte_size(NameBin),
            CtlInfo = <<0:32, NameBin/binary, 0:(Padding*8)>>,
            case procket:ioctl(Socket, 16#c0644e03, CtlInfo) of
                {ok, <<CtlId:32/native, _/binary>>} ->
                    SockAddrCtl = <<32:8, 32:8, 2:16/native, CtlId:32/native, Unit:32/native, 0:(20*8)>>,
                    case procket:connect(Socket, SockAddrCtl) of
                        ok ->
                            case procket:getsockopt(Socket, 2, 2, <<0:256>>) of
                                {ok, RawIfName} ->
                                    [ActualName | _] = binary:split(RawIfName, <<0>>),
                                    logger:info("macOS utun interface opened: requested=~s (unit ~p) allocated=~s fd=~p", [Name, Unit, ActualName, Socket]),
                                    case parse_ip(Ip) of
                                        {ok, Addr} ->
                                            IpStr = inet_parse:ntoa(Addr),
                                            PeerAddr = calculate_peer_ip(Addr),
                                            PeerIpStr = inet_parse:ntoa(PeerAddr),
                                            Cmd = "sudo ifconfig " ++ binary_to_list(ActualName) ++ " " ++ IpStr ++ " " ++ PeerIpStr ++ " up",
                                            case os:cmd(Cmd) of
                                                [] ->
                                                    try erlang:open_port({fd, Socket, Socket}, [binary, stream]) of
                                                        Port ->
                                                            {ok, {utun_port, Port, Socket, ActualName}}
                                                    catch
                                                        error:Err ->
                                                            procket:close(Socket),
                                                            {error, {port_open_failed, Err}}
                                                    end;
                                                Error ->
                                                    procket:close(Socket),
                                                    {error, {ip_config_failed, Error}}
                                            end;
                                        {error, Reason} ->
                                            procket:close(Socket),
                                            {error, {invalid_ip_format, Reason}}
                                    end;
                                {error, Reason} ->
                                    procket:close(Socket),
                                    {error, {getsockopt_failed, Reason}}
                            end;
                        {error, ebusy} ->
                            procket:close(Socket),
                            logger:debug("utun unit ~p is busy, trying next unit", [Unit]),
                            open_utun_try(Unit + 1, Name, Ip);
                        {error, Reason} ->
                            procket:close(Socket),
                            {error, {connect_failed, Reason}}
                    end;
                {error, Reason} ->
                    procket:close(Socket),
                    {error, {ioctl_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {socket_failed, Reason}}
    end.

parse_unit(Name) when is_binary(Name) ->
    parse_unit(binary_to_list(Name));
parse_unit(Name) when is_list(Name) ->
    case re:run(Name, "u?tun([0-9]+)", [{capture, [1], list}]) of
        {match, [Digits]} ->
            list_to_integer(Digits) + 1;
        _ ->
            0
    end.

parse_ip(Ip) when is_list(Ip) ->
    inet_parse:address(Ip);
parse_ip(Ip) when is_tuple(Ip) ->
    {ok, Ip};
parse_ip(Ip) when is_binary(Ip) ->
    inet_parse:address(binary_to_list(Ip)).

family_header(<<4:4, _/bits>>) -> <<2:32/big>>;
family_header(<<6:4, _/bits>>) -> <<30:32/big>>;
family_header(_) -> <<2:32/big>>.

calculate_peer_ip({A, B, C, D}) ->
    {A, B, C, D bxor 3};
calculate_peer_ip(Other) ->
    Other.
