-module(vpn_runtime_config_resolver).

-export([resolve/2, mode/0, validate_certificate_fingerprint/2]).

resolve(PeerId, Desired) when is_map(Desired) ->
    case mode() of
        disabled ->
            {error, runtime_config_required};
        static_template ->
            resolve_static_template(PeerId, Desired);
        Resolver ->
            {error, {unsupported_runtime_config_resolver, Resolver}}
    end.

mode() ->
    case application:get_env(vpn, runtime_config_resolver, disabled) of
        <<"disabled">> -> disabled;
        <<"static_template">> -> static_template;
        Value -> Value
    end.

resolve_static_template(PeerId, Desired) ->
    case application:get_env(vpn, runtime_config_template) of
        {ok, Template} when is_map(Template) ->
            resolve_template(PeerId, Desired, sanitize_template(Template));
        {ok, _Other} ->
            {error, invalid_runtime_config_template};
        undefined ->
            {error, runtime_config_required}
    end.

resolve_template(PeerId, Desired, Template) ->
    Candidate = template_with_identity(PeerId, Desired, Template),
    case maps:is_key(ovpn_path, Candidate) of
        true ->
            case vpn_session_config:from_spec(Candidate) of
                {ok, #{peer_config := PeerConfig}} ->
                    case validate_certificate_fingerprint(Desired, PeerConfig) of
                        ok -> {ok, PeerConfig};
                        {error, _} = Error -> Error
                    end;
                {error, Reason} -> {error, Reason}
            end;
        false ->
            validate_direct_runtime(Candidate)
    end.

validate_direct_runtime(Candidate) ->
    case vpn_peer:validate_runtime_config(Candidate) of
        ok -> {ok, Candidate};
        {error, Reason} -> {error, Reason}
    end.

validate_certificate_fingerprint(Desired, PeerConfig)
  when is_map(Desired), is_map(PeerConfig) ->
    case maps:get(certificate_fingerprint, Desired, undefined) of
        undefined ->
            ok;
        Expected ->
            case actual_certificate_fingerprint(PeerConfig) of
                undefined -> {error, certificate_fingerprint_unavailable};
                Expected -> ok;
                _Actual -> {error, certificate_fingerprint_mismatch}
            end
    end.

actual_certificate_fingerprint(PeerConfig) ->
    case maps:get(ovpn_identity, PeerConfig, undefined) of
        Identity when is_map(Identity) ->
            maps:get(certificate_fingerprint,
                     Identity,
                     maps:get(certificate_fingerprint, PeerConfig, undefined));
        _ ->
            maps:get(certificate_fingerprint, PeerConfig, undefined)
    end.

template_with_identity(PeerId, Desired, Template) ->
    Base = maps:remove(id, Template),
    Identity = maps:with([device_id,
                          certificate_fingerprint,
                          authorization_mode,
                          authorized,
                          authorization_reason],
                         Desired),
    maps:merge(Base#{id => PeerId}, Identity).

sanitize_template(Template) ->
    maps:with(allowed_template_keys(), Template).

allowed_template_keys() ->
    [id,
     name,
     peer_module,
     mode,
     ifname,
     ip,
     local_udp_port,
     remote_ip,
     remote_udp_port,
     remote_peer_id,
     psk,
     certificate_path,
     private_key_path,
     ca_certificate_path,
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
     handshake_remote_ca_certificate_path,
     debug_replay_controls,
     device_id,
     certificate_fingerprint].
