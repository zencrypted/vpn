%%%-------------------------------------------------------------------
%% @doc Runtime peer abstraction over vpn_link.
%%%-------------------------------------------------------------------
-module(vpn_peer).

-behaviour(gen_server).

-export([start_link/1, stop/1, stats/1, reset_stats/1, rekey/1, debug_frame_history/1, debug_replay_frame/3, debug_send_frames/2,
         debug_send_payload/2, debug_received_payloads/1, debug_clear_received_payloads/1,
         debug_session_state/1,
         identity/1, identity_info/1, config/1, validate_runtime_config/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

start_link(Config) ->
    gen_server:start_link(?MODULE, Config, []).

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

debug_send_payload(Pid, Payload) when is_binary(Payload) ->
    gen_server:call(Pid, {debug_send_payload, Payload}, 30000).

debug_received_payloads(Pid) ->
    gen_server:call(Pid, debug_received_payloads).

debug_clear_received_payloads(Pid) ->
    gen_server:call(Pid, debug_clear_received_payloads).

debug_session_state(Pid) ->
    gen_server:call(Pid, debug_session_state).

identity(Pid) ->
    gen_server:call(Pid, identity).

identity_info(Pid) ->
    gen_server:call(Pid, identity_info).

config(Pid) ->
    gen_server:call(Pid, config).

init(Config) ->
    process_flag(trap_exit, true),
    case validate_runtime_config(Config) of
        ok ->
            start_link_with_identity(Config);
        {error, Reason} ->
            {stop, Reason}
    end.

validate_runtime_config(Config) ->
    validate_config(Config).

handle_call(stats, _From, State = #{id := Id, link_pid := LinkPid}) ->
    LinkStats = vpn_link:stats(LinkPid),
    {reply, #{id => Id, link => LinkStats}, State};
handle_call(reset_stats, _From, State = #{link_pid := LinkPid}) ->
    {reply, vpn_link:reset_stats(LinkPid), State};
handle_call(rekey, _From, State = #{link_pid := LinkPid}) ->
    {reply, vpn_link:rekey(LinkPid), State};
handle_call(debug_frame_history, _From, State = #{link_pid := LinkPid}) ->
    {reply, vpn_link:debug_frame_history(LinkPid), State};
handle_call({debug_replay_frame, KeyEpoch, Seq}, _From,
            State = #{link_pid := LinkPid}) ->
    {reply, vpn_link:debug_replay_frame(LinkPid, KeyEpoch, Seq), State};
handle_call({debug_send_frames, Count}, _From, State = #{link_pid := LinkPid}) ->
    {reply, vpn_link:debug_send_frames(LinkPid, Count), State};
handle_call({debug_send_payload, Payload}, _From, State = #{link_pid := LinkPid}) ->
    {reply, vpn_link:debug_send_payload(LinkPid, Payload), State};
handle_call(debug_received_payloads, _From, State = #{link_pid := LinkPid}) ->
    {reply, vpn_link:debug_received_payloads(LinkPid), State};
handle_call(debug_clear_received_payloads, _From, State = #{link_pid := LinkPid}) ->
    {reply, vpn_link:debug_clear_received_payloads(LinkPid), State};
handle_call(debug_session_state, _From, State = #{link_pid := LinkPid}) ->
    {reply, vpn_link:debug_session_state(LinkPid), State};
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
    Psk = maps:get(psk, Config, undefined),
    HandshakeOptions = handshake_options(Config, IdentityInfo),
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


handshake_options(Config, IdentityInfo) ->
    Base = #{mode => maps:get(handshake_mode, Config, disabled),
             retry_interval => maps:get(handshake_retry_interval, Config, 1000),
             max_retries => maps:get(handshake_max_retries, Config, 5),
             previous_epoch_grace_ms =>
                 maps:get(previous_epoch_grace_ms, Config, 5000),
             debug_replay_controls =>
                 maps:get(debug_replay_controls, Config, false),
             auto_rekey_after_seconds =>
                 maps:get(auto_rekey_after_seconds, Config, 0),
             auto_rekey_after_packets =>
                 maps:get(auto_rekey_after_packets, Config, 0),
             auto_rekey_check_interval_ms =>
                 maps:get(auto_rekey_check_interval_ms, Config, 1000),
             auto_rekey_failure_cooldown_ms =>
                 maps:get(auto_rekey_failure_cooldown_ms, Config, 5000),
             auto_rekey_jitter_ms =>
                 maps:get(auto_rekey_jitter_ms, Config, 0)},
    case maps:get(handshake_mode, Config, disabled) of
        certificate_control ->
            Base#{local_certificate_pem => maps:get(certificate_pem, IdentityInfo),
                  local_private_key_path => maps:get(private_key_path, IdentityInfo),
                  remote_ca_certificate_path => maps:get(handshake_remote_ca_certificate_path,
                                                         Config)};
        _ ->
            Base
    end.

validate_config(Config) when is_map(Config) ->
    case missing_key(Config) of
        none ->
            case validate_mode(maps:get(mode, Config)) of
                ok -> validate_handshake_config(Config);
                {error, _} = Error -> Error
            end;
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
              remote_peer_id],
    Required = case maps:get(handshake_mode, Config, disabled) of
                   certificate_control -> Common;
                   _ -> Common ++ [psk]
               end,
    case missing_key(Config, Required) of
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

validate_handshake_config(#{handshake_mode := certificate_control} = Config) ->
    case maps:get(handshake_remote_ca_certificate_path, Config, undefined) of
        Path when is_list(Path); is_binary(Path) ->
            validate_previous_epoch_grace(Config);
        _ ->
            {error, {missing_config_key, handshake_remote_ca_certificate_path}}
    end;
validate_handshake_config(Config) ->
    validate_previous_epoch_grace(Config).

validate_previous_epoch_grace(Config) ->
    case maps:get(previous_epoch_grace_ms, Config, 5000) of
        GraceMs when is_integer(GraceMs), GraceMs > 0 ->
            validate_debug_replay_controls(Config);
        GraceMs ->
            {error, {invalid_previous_epoch_grace_ms, GraceMs}}
    end.

validate_debug_replay_controls(Config) ->
    case maps:get(debug_replay_controls, Config, false) of
        Value when is_boolean(Value) -> validate_auto_rekey_config(Config);
        Value -> {error, {invalid_debug_replay_controls, Value}}
    end.

validate_auto_rekey_config(Config) ->
    Values = [{auto_rekey_after_seconds, maps:get(auto_rekey_after_seconds, Config, 0)},
              {auto_rekey_after_packets, maps:get(auto_rekey_after_packets, Config, 0)}],
    case [{Key, Value} || {Key, Value} <- Values,
                          not (is_integer(Value) andalso Value >= 0)] of
        [] ->
            case auto_rekey_enabled_in_config(Config) andalso
                 maps:get(handshake_mode, Config, disabled) =/= certificate_control of
                true -> {error, auto_rekey_requires_certificate_control};
                false -> validate_positive_auto_rekey_value(auto_rekey_check_interval_ms,
                                                             maps:get(auto_rekey_check_interval_ms, Config, 1000),
                                                             Config)
            end;
        [{Key, Value} | _] -> {error, {invalid_auto_rekey_value, Key, Value}}
    end.

auto_rekey_enabled_in_config(Config) ->
    maps:get(auto_rekey_after_seconds, Config, 0) > 0 orelse
    maps:get(auto_rekey_after_packets, Config, 0) > 0.

validate_positive_auto_rekey_value(Key, Value, Config)
  when is_integer(Value), Value > 0 ->
    case Key of
        auto_rekey_check_interval_ms ->
            validate_positive_auto_rekey_value(auto_rekey_failure_cooldown_ms,
                                               maps:get(auto_rekey_failure_cooldown_ms, Config, 5000),
                                               Config);
        auto_rekey_failure_cooldown_ms ->
            validate_nonnegative_auto_rekey_value(auto_rekey_jitter_ms,
                                                  maps:get(auto_rekey_jitter_ms, Config, 0))
    end;
validate_positive_auto_rekey_value(Key, Value, _Config) ->
    {error, {invalid_auto_rekey_value, Key, Value}}.

validate_nonnegative_auto_rekey_value(_Key, Value)
  when is_integer(Value), Value >= 0 ->
    ok;
validate_nonnegative_auto_rekey_value(Key, Value) ->
    {error, {invalid_auto_rekey_value, Key, Value}}.

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
               handshake_max_retries,
               previous_epoch_grace_ms,
               auto_rekey_after_seconds,
               auto_rekey_after_packets,
               auto_rekey_check_interval_ms,
               auto_rekey_failure_cooldown_ms,
               auto_rekey_jitter_ms,
               handshake_remote_ca_certificate_path],
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
