%%%-------------------------------------------------------------------
%% @doc Runtime peer abstraction over vpn_link.
%%%-------------------------------------------------------------------
-module(vpn_peer).

-behaviour(gen_server).

-export([start_link/1, stop/1, stats/1, reset_stats/1, identity/1, identity_info/1, config/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

start_link(Config) ->
    gen_server:start_link(?MODULE, Config, []).

stop(Pid) ->
    gen_server:stop(Pid).

stats(Pid) ->
    gen_server:call(Pid, stats).

reset_stats(Pid) ->
    gen_server:call(Pid, reset_stats).

identity(Pid) ->
    gen_server:call(Pid, identity).

identity_info(Pid) ->
    gen_server:call(Pid, identity_info).

config(Pid) ->
    gen_server:call(Pid, config).

init(Config) ->
    process_flag(trap_exit, true),
    case validate_config(Config) of
        ok ->
            start_link_with_identity(Config);
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(stats, _From, State = #{id := Id, link_pid := LinkPid}) ->
    LinkStats = vpn_link:stats(LinkPid),
    {reply, #{id => Id, link => LinkStats}, State};
handle_call(reset_stats, _From, State = #{link_pid := LinkPid}) ->
    {reply, vpn_link:reset_stats(LinkPid), State};
handle_call(identity, _From, State = #{identity := Identity}) ->
    {reply, Identity, State};
handle_call(identity_info, _From, State = #{identity_info := IdentityInfo}) ->
    {reply, safe_identity_info(IdentityInfo), State};
handle_call(config, _From, State = #{config := Config}) ->
    {reply, runtime_config(Config), State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({'EXIT', LinkPid, Reason}, State = #{link_pid := LinkPid}) ->
    {stop, {link_exit, Reason}, State};
handle_info(_Message, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    stop_link(maps:get(link_pid, State, undefined)),
    ok.

start_link_with_identity(Config0) ->
    case maps:take(ovpn_identity, Config0) of
        {IdentityInfo, Config} ->
            case maps:get(identity_ready, IdentityInfo, false) of
                true ->
                    case validate_ovpn_authorization(Config) of
                        ok -> start_link_from_config(Config, IdentityInfo);
                        {error, Reason} -> {stop, Reason}
                    end;
                false -> {stop, ovpn_identity_not_ready}
            end;
        error ->
            case vpn_identity:load(Config0) of
                {ok, IdentityInfo} ->
                    start_link_from_config(Config0, IdentityInfo);
                {error, Reason} ->
                    {stop, Reason}
            end
    end.

validate_ovpn_authorization(#{authorization_mode := development_bypass,
                              authorized := true}) ->
    ok;
validate_ovpn_authorization(#{authorization_mode := policy,
                              authorized := true}) ->
    ok;
validate_ovpn_authorization(Config) ->
    {error, {authorization_denied,
             maps:get(authorization_reason, Config, policy_authorization_required)}}.

start_link_from_config(Config, IdentityInfo) ->
    Id = maps:get(id, Config),
    Mode = maps:get(mode, Config),
    IfName = maps:get(ifname, Config),
    Ip = maps:get(ip, Config),
    LocalUdpPort = maps:get(local_udp_port, Config),
    RemoteIp = maps:get(remote_ip, Config),
    RemoteUdpPort = maps:get(remote_udp_port, Config),
    RemotePeerId = maps:get(remote_peer_id, Config),
    Psk = maps:get(psk, Config),
    HandshakeOptions = #{mode => maps:get(handshake_mode, Config, disabled),
                         retry_interval => maps:get(handshake_retry_interval, Config, 1000),
                         max_retries => maps:get(handshake_max_retries, Config, 5)},
    Identity = identity_from_config(Config),
    case vpn_link:start_link(IfName,
                             Ip,
                             Mode,
                             LocalUdpPort,
                             RemoteIp,
                             RemoteUdpPort,
                             Id,
                             RemotePeerId,
                             Psk,
                             HandshakeOptions) of
        {ok, LinkPid} ->
            logger:info("vpn_peer started: ~p", [Id]),
            {ok, #{id => Id,
                   config => Config,
                   identity => Identity,
                   identity_info => IdentityInfo,
                   link_pid => LinkPid}};
        {error, Reason} ->
            {stop, Reason}
    end.

validate_config(Config) when is_map(Config) ->
    case missing_key(Config) of
        none ->
            validate_mode(maps:get(mode, Config));
        {missing, Key} ->
            {error, {missing_config_key, Key}}
    end;
validate_config(_Config) ->
    {error, invalid_config}.

missing_key(Config) ->
    Common = [id,
              mode,
              ifname,
              ip,
              local_udp_port,
              remote_ip,
              remote_udp_port,
              remote_peer_id,
              psk],
    case missing_key(Config, Common) of
        none -> missing_identity_key(Config);
        Missing -> Missing
    end.

missing_identity_key(Config) ->
    case maps:is_key(ovpn_identity, Config) of
        true -> none;
        false ->
            missing_key(Config,
                        [certificate_path,
                         private_key_path,
                         ca_certificate_path])
    end.

missing_key(_Config, []) ->
    none;
missing_key(Config, [Key | Rest]) ->
    case maps:is_key(Key, Config) of
        true ->
            missing_key(Config, Rest);
        false ->
            {missing, Key}
    end.

validate_mode(tap) ->
    ok;
validate_mode(tun) ->
    ok;
validate_mode(Mode) ->
    {error, {invalid_mode, Mode}}.

identity_from_config(Config) ->
    #{id => maps:get(id, Config),
      name => maps:get(name, Config, undefined),
      certificate_path => maps:get(certificate_path, Config, undefined),
      private_key_path => maps:get(private_key_path, Config, undefined),
      ca_certificate_path => maps:get(ca_certificate_path, Config, undefined),
      ovpn_path => maps:get(ovpn_path, Config, undefined)}.

runtime_config(Config) ->
    maps:with([id,
               mode,
               ifname,
               ip,
               local_udp_port,
               remote_ip,
               remote_udp_port,
               remote_peer_id,
               ovpn_path,
               authorization_mode,
               authorized,
               authorization_reason,
               handshake_mode,
               handshake_retry_interval,
               handshake_max_retries],
              Config).

safe_identity_info(#{identity_ready := _} = IdentityInfo) ->
    vpn_ovpn_identity:safe_info(IdentityInfo);
safe_identity_info(IdentityInfo) ->
    vpn_identity:safe_info(IdentityInfo).

stop_link(undefined) ->
    ok;
stop_link(LinkPid) ->
    case is_process_alive(LinkPid) of
        true ->
            _ = vpn_link:stop(LinkPid),
            ok;
        false ->
            ok
    end.
