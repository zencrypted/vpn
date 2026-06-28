%%%-------------------------------------------------------------------
%% @doc Builds a runtime peer configuration from a validated OVPN envelope.
%%
%% OVPN supplies the remote endpoint, tunnel mode, CA, certificate, and
%% Device-local private-key reference. Runtime-only values remain in trusted
%% application configuration and are never read from OVPN comments.
%%%-------------------------------------------------------------------
-module(vpn_session_config).

-export([load/2, from_spec/1, configured_peers/0, safe_info/1]).

-spec load(file:filename_all(), map()) -> {ok, map()} | {error, term()}.
load(OvpnPath, Runtime0) when is_map(Runtime0) ->
    case validate_runtime(Runtime0) of
        ok ->
            load_identity(OvpnPath, Runtime0);
        {error, _} = Error ->
            Error
    end;
load(_OvpnPath, _Runtime) ->
    {error, invalid_runtime_config}.

-spec from_spec(map()) -> {ok, map()} | {error, term()}.
from_spec(Spec) when is_map(Spec) ->
    case maps:take(ovpn_path, Spec) of
        {OvpnPath, Runtime} ->
            load(OvpnPath, Runtime);
        error ->
            {error, {missing_session_key, ovpn_path}}
    end;
from_spec(_Spec) ->
    {error, invalid_session_spec}.

-spec configured_peers() -> {ok, [map()]} | {error, term()}.
configured_peers() ->
    LegacyPeers = application:get_env(vpn, peers, []),
    SessionSpecs = application:get_env(vpn, ovpn_sessions, []),
    case load_specs(SessionSpecs, []) of
        {ok, SessionPeers} ->
            {ok, LegacyPeers ++ SessionPeers};
        {error, _} = Error ->
            Error
    end.

-spec safe_info(map()) -> map().
safe_info(Session) ->
    maps:with([peer_id, ovpn_path, endpoint, tunnel, identity, authorization], Session).

load_identity(OvpnPath, Runtime) ->
    case vpn_ovpn_identity:load(OvpnPath) of
        {ok, Identity} ->
            Config = maps:get(config, Identity),
            build_session(Runtime, Identity, Config);
        {error, Reason} ->
            {error, {ovpn_identity_failed, Reason}}
    end.

build_session(Runtime0, Identity, OvpnConfig) ->
    Authorization = authorization(Runtime0),
    Runtime = Runtime0#{authorization_mode => maps:get(mode, Authorization),
                        authorized => maps:get(authorized, Authorization),
                        authorization_reason => maps:get(reason, Authorization)},
    PeerId = maps:get(id, Runtime),
    RemoteHost = maps:get(remote_host, OvpnConfig),
    RemotePort = maps:get(remote_port, OvpnConfig),
    Mode = maps:get(tunnel_device, OvpnConfig),
    OvpnPath = maps:get(ovpn_path, Identity),
    PeerConfig0 = Runtime#{mode => Mode,
                           remote_ip => host_value(RemoteHost),
                           remote_udp_port => RemotePort,
                           ovpn_path => OvpnPath,
                           ovpn_identity => Identity},
    PeerConfig = maps:remove(remote_host, PeerConfig0),
    SafeIdentity = vpn_ovpn_identity:safe_info(Identity),
    {ok, #{peer_id => PeerId,
           ovpn_path => OvpnPath,
           endpoint => #{host => RemoteHost,
                         port => RemotePort,
                         transport => maps:get(transport, OvpnConfig)},
           tunnel => #{device => Mode,
                       ifname => maps:get(ifname, Runtime),
                       ip => maps:get(ip, Runtime)},
           identity => SafeIdentity,
           authorization => Authorization,
           peer_config => PeerConfig}}.

validate_runtime(Runtime) ->
    Common = [id, ifname, ip, local_udp_port, remote_peer_id],
    Required = case maps:get(handshake_mode, Runtime, disabled) of
                   certificate_control -> Common;
                   _ -> Common ++ [psk]
               end,
    case missing_key(Runtime, Required) of
        none ->
            case validate_runtime_values(Runtime) of
                ok -> validate_authorization(Runtime);
                {error, _} = Error -> Error
            end;
        {missing, Key} ->
            {error, {missing_runtime_key, Key}}
    end.

validate_runtime_values(Runtime = #{id := Id,
                          ifname := IfName,
                          ip := Ip,
                          local_udp_port := Port,
                          remote_peer_id := RemotePeerId})
  when (is_atom(Id) orelse is_binary(Id)),
       (is_binary(IfName) orelse is_list(IfName)),
       is_list(Ip),
       is_integer(Port), Port > 0, Port =< 65535,
       (is_atom(RemotePeerId) orelse is_binary(RemotePeerId)) ->
    case validate_key_source(Runtime) of
        ok ->
            case maps:get(authorization_mode, Runtime, policy) of
                development_bypass -> ok;
                policy -> ok;
                _ -> {error, invalid_authorization_mode}
            end;
        {error, _} = Error -> Error
    end;
validate_runtime_values(_Runtime) ->
    {error, invalid_runtime_values}.

validate_key_source(#{handshake_mode := certificate_control}) -> ok;
validate_key_source(#{psk := Psk}) when is_binary(Psk), byte_size(Psk) >= 16 -> ok;
validate_key_source(_) -> {error, invalid_psk}.

validate_authorization(Runtime) ->
    case authorization(Runtime) of
        #{authorized := true} ->
            ok;
        #{mode := policy, reason := Reason} ->
            {error, {authorization_denied, Reason}}
    end.

authorization(Runtime) ->
    case maps:get(authorization_mode, Runtime, policy) of
        development_bypass ->
            #{mode => development_bypass,
              authorized => true,
              reason => development_bypass};
        policy ->
            #{mode => policy,
              authorized => maps:get(authorized, Runtime, false),
              reason => maps:get(authorization_reason, Runtime, policy_authorization_required)}
    end.

missing_key(_Map, []) ->
    none;
missing_key(Map, [Key | Rest]) ->
    case maps:is_key(Key, Map) of
        true -> missing_key(Map, Rest);
        false -> {missing, Key}
    end.

load_specs([], Acc) ->
    {ok, lists:reverse(Acc)};
load_specs([Spec | Rest], Acc) ->
    SessionId = session_id(Spec),
    case from_spec(Spec) of
        {ok, #{peer_config := PeerConfig}} ->
            load_specs(Rest, [PeerConfig | Acc]);
        {error, Reason} ->
            {error, {invalid_ovpn_session, SessionId, Reason}}
    end;
load_specs(_ImproperList, _Acc) ->
    {error, invalid_ovpn_sessions}.

session_id(Spec) when is_map(Spec) ->
    maps:get(id, Spec, undefined);
session_id(_Spec) ->
    undefined.

host_value(Host) when is_binary(Host) ->
    binary_to_list(Host);
host_value(Host) ->
    Host.
