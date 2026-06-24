-module(vpn_runtime_config_resolver).

-export([resolve/2,
         resolve_pair/2,
         mode/0,
         validate_certificate_fingerprint/2]).

resolve(PeerId, Desired) when is_map(Desired) ->
    case mode() of
        disabled ->
            {error, runtime_config_required};
        static_template ->
            resolve_static_template(PeerId, Desired);
        dynamic_allocator ->
            resolve_dynamic_allocation(PeerId, Desired);
        Resolver ->
            {error, {unsupported_runtime_config_resolver, Resolver}}
    end.

%% @doc Resolve both sides of an existing allocator reservation.
%%
%% This function is deliberately lookup-only. Reservation ownership remains
%% explicit: callers must invoke vpn_peer_allocator:ensure/1 before identity
%% issuance or provisioning. Transport fields always come from the allocator;
%% Desired contributes only client identity and authorization metadata.
resolve_pair(DeviceId, Desired)
  when is_binary(DeviceId), byte_size(DeviceId) > 0, is_map(Desired) ->
    case desired_device_matches(DeviceId, Desired) of
        ok ->
            case vpn_peer_allocator:lookup(DeviceId) of
                {ok, Allocation} ->
                    resolve_dynamic_pair(Allocation, Desired);
                {error, not_found} ->
                    {error, {dynamic_peer_allocation_required, DeviceId}};
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end;
resolve_pair(_DeviceId, _Desired) ->
    {error, invalid_device_id}.

mode() ->
    case application:get_env(vpn, runtime_config_resolver, disabled) of
        <<"disabled">> -> disabled;
        <<"static_template">> -> static_template;
        <<"dynamic_allocator">> -> dynamic_allocator;
        Value -> Value
    end.

resolve_static_template(PeerId, Desired) ->
    case static_template(PeerId) of
        {ok, Template} ->
            resolve_template(PeerId, Desired, sanitize_template(Template));
        {error, _} = Error ->
            Error
    end.

resolve_dynamic_allocation(PeerId, Desired) ->
    case maps:get(device_id, Desired, undefined) of
        DeviceId when is_binary(DeviceId), byte_size(DeviceId) > 0 ->
            case resolve_pair(DeviceId, Desired) of
                {ok, #{client := #{id := PeerId} = Client}} ->
                    {ok, Client};
                {ok, #{gateway := #{id := PeerId} = Gateway}} ->
                    {ok, Gateway};
                {ok, _Pair} ->
                    {error, {dynamic_peer_not_in_allocation, PeerId}};
                {error, _} = Error ->
                    Error
            end;
        _ ->
            {error, dynamic_peer_device_id_required}
    end.

resolve_dynamic_pair(Allocation, Desired) ->
    case dynamic_runtime_defaults() of
        {ok, Defaults} ->
            case dynamic_identity_bundle(Allocation) of
                {ok, IdentityBundle} ->
                    ClientSpec = dynamic_runtime_config(client,
                                                        Allocation,
                                                        Desired,
                                                        Defaults,
                                                        IdentityBundle),
                    GatewaySpec = dynamic_runtime_config(gateway,
                                                         Allocation,
                                                         Desired,
                                                         Defaults,
                                                         IdentityBundle),
                    materialize_dynamic_pair(Allocation,
                                             ClientSpec,
                                             GatewaySpec,
                                             Desired);
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

dynamic_runtime_config(Role, Allocation, Desired, Defaults, IdentityBundle) ->
    Endpoint = maps:get(Role, Allocation),
    Common = maps:get(common, Defaults, #{}),
    RoleDefaults = maps:get(Role, Defaults, #{}),
    TrustedDefaults = maps:merge(Common, RoleDefaults),
    Transport = maps:with([ifname,
                           ip,
                           local_udp_port,
                           remote_ip,
                           remote_udp_port,
                           remote_peer_id],
                          Endpoint),
    PeerId = maps:get(peer_id, Endpoint),
    AllocationMetadata =
        #{id => PeerId,
          device_id => maps:get(device_id, Allocation),
          allocation_id => maps:get(allocation_id, Allocation),
          allocation_slot => maps:get(slot, Allocation),
          allocation_generation => maps:get(generation, Allocation),
          allocation_role => Role},
    Identity = dynamic_identity_refs(Role, IdentityBundle),
    Base = maps:merge(TrustedDefaults,
                      maps:merge(Transport,
                                 maps:merge(AllocationMetadata, Identity))),
    case Role of
        client -> maps:merge(Base, dynamic_client_identity(Desired));
        gateway -> Base
    end.

materialize_dynamic_pair(Allocation, ClientSpec, GatewaySpec, Desired) ->
    case vpn_session_config:from_spec(ClientSpec) of
        {ok, #{peer_config := Client}} ->
            case validate_direct_runtime(GatewaySpec) of
                {ok, Gateway} ->
                    case validate_certificate_fingerprint(Desired, Client) of
                        ok ->
                            {ok, #{allocation_id => maps:get(allocation_id, Allocation),
                                   device_id => maps:get(device_id, Allocation),
                                   client => Client,
                                   gateway => Gateway}};
                        {error, _} = Error -> Error
                    end;
                {error, _} = Error -> Error
            end;
        {error, Reason} ->
            {error, {dynamic_client_identity_failed, Reason}}
    end.

dynamic_identity_bundle(Allocation) ->
    AllocationId = maps:get(allocation_id, Allocation),
    Provider = application:get_env(vpn,
                                   dynamic_identity_factory_module,
                                   vpn_dynamic_identity_factory),
    try Provider:lookup(AllocationId) of
        {ok, Bundle} -> validate_dynamic_identity_bundle(Allocation, Bundle);
        {error, LookupReason} ->
            {error, {dynamic_identity_required, AllocationId, LookupReason}};
        Other ->
            {error, {invalid_dynamic_identity_provider_result, Other}}
    catch
        Class:CatchReason ->
            {error, {dynamic_identity_provider_failed,
                     Provider,
                     Class,
                     CatchReason}}
    end.

validate_dynamic_identity_bundle(
  Allocation,
  #{allocation_id := AllocationId,
    device_id := DeviceId,
    client := #{peer_id := ClientPeerId,
                ovpn_path := OvpnPath,
                ca_certificate_path := ClientCaPath},
    gateway := #{peer_id := GatewayPeerId,
                 certificate_path := GatewayCertPath,
                 private_key_path := GatewayKeyPath,
                 ca_certificate_path := GatewayCaPath}} = Bundle) ->
    case {AllocationId =:= maps:get(allocation_id, Allocation),
          DeviceId =:= maps:get(device_id, Allocation),
          ClientPeerId =:= maps:get(client_peer_id, Allocation),
          GatewayPeerId =:= maps:get(gateway_peer_id, Allocation),
          valid_identity_path(OvpnPath),
          valid_identity_path(ClientCaPath),
          valid_identity_path(GatewayCertPath),
          valid_identity_path(GatewayKeyPath),
          valid_identity_path(GatewayCaPath)} of
        {true, true, true, true, true, true, true, true, true} ->
            {ok, Bundle};
        {false, _, _, _, _, _, _, _, _} ->
            {error, dynamic_identity_allocation_mismatch};
        {_, false, _, _, _, _, _, _, _} ->
            {error, dynamic_identity_allocation_mismatch};
        {_, _, false, _, _, _, _, _, _} ->
            {error, dynamic_identity_allocation_mismatch};
        {_, _, _, false, _, _, _, _, _} ->
            {error, dynamic_identity_allocation_mismatch};
        _ ->
            {error, invalid_dynamic_identity_bundle}
    end;
validate_dynamic_identity_bundle(_Allocation, _Bundle) ->
    {error, invalid_dynamic_identity_bundle}.

valid_identity_path(Path) when is_list(Path) -> Path =/= [];
valid_identity_path(Path) when is_binary(Path) -> byte_size(Path) > 0;
valid_identity_path(_) -> false.

dynamic_identity_refs(client,
                      #{client := #{ovpn_path := OvpnPath,
                                    ca_certificate_path := CaPath}}) ->
    #{ovpn_path => OvpnPath,
      handshake_remote_ca_certificate_path => CaPath};
dynamic_identity_refs(gateway,
                      #{gateway := #{certificate_path := CertPath,
                                     private_key_path := KeyPath,
                                     ca_certificate_path := CaPath}}) ->
    #{certificate_path => CertPath,
      private_key_path => KeyPath,
      ca_certificate_path => CaPath,
      handshake_remote_ca_certificate_path => CaPath}.

dynamic_runtime_defaults() ->
    case application:get_env(vpn, dynamic_runtime_config_defaults) of
        {ok, Defaults} when is_map(Defaults) ->
            validate_dynamic_runtime_defaults(Defaults);
        {ok, _Other} ->
            {error, invalid_dynamic_runtime_config_defaults};
        undefined ->
            {error, dynamic_runtime_config_defaults_required}
    end.

validate_dynamic_runtime_defaults(Defaults) ->
    AllowedSections = [common, client, gateway],
    case [Key || Key <- maps:keys(Defaults),
                 not lists:member(Key, AllowedSections)] of
        [InvalidSection | _] ->
            {error, {invalid_dynamic_runtime_config_section, InvalidSection}};
        [] ->
            validate_dynamic_runtime_default_sections(AllowedSections, Defaults)
    end.

validate_dynamic_runtime_default_sections([], Defaults) ->
    {ok, Defaults};
validate_dynamic_runtime_default_sections([Section | Rest], Defaults) ->
    case maps:get(Section, Defaults, #{}) of
        SectionDefaults when is_map(SectionDefaults) ->
            case validate_dynamic_runtime_default_keys(SectionDefaults) of
                ok -> validate_dynamic_runtime_default_sections(Rest, Defaults);
                {error, _} = Error -> Error
            end;
        _Other ->
            {error, {invalid_dynamic_runtime_config_section, Section}}
    end.

validate_dynamic_runtime_default_keys(Defaults) ->
    Allowed = allowed_dynamic_default_keys(),
    case [Key || Key <- maps:keys(Defaults), not lists:member(Key, Allowed)] of
        [InvalidKey | _] ->
            {error, {dynamic_runtime_transport_or_unknown_key, InvalidKey}};
        [] ->
            ok
    end.

static_template(PeerId) ->
    case application:get_env(vpn, runtime_config_templates) of
        {ok, Templates} when is_map(Templates) ->
            case maps:find(PeerId, Templates) of
                {ok, Template} when is_map(Template) -> {ok, Template};
                {ok, _Other} -> {error, invalid_runtime_config_template};
                error -> {error, {runtime_config_template_not_found, PeerId}}
            end;
        {ok, _Other} ->
            {error, invalid_runtime_config_templates};
        undefined ->
            legacy_static_template()
    end.

legacy_static_template() ->
    case application:get_env(vpn, runtime_config_template) of
        {ok, Template} when is_map(Template) -> {ok, Template};
        {ok, _Other} -> {error, invalid_runtime_config_template};
        undefined -> {error, runtime_config_required}
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

desired_device_matches(DeviceId, Desired) ->
    case maps:get(device_id, Desired, DeviceId) of
        DeviceId -> ok;
        _Other -> {error, dynamic_peer_device_id_mismatch}
    end.

dynamic_client_identity(Desired) ->
    maps:with([profile_id,
               certificate_fingerprint,
               authorization_mode,
               authorized,
               authorization_reason,
               enabled,
               revoked],
              Desired).

template_with_identity(PeerId, Desired, Template) ->
    Base = maps:remove(id, Template),
    Identity = maps:with([device_id,
                          profile_id,
                          certificate_fingerprint,
                          authorization_mode,
                          authorized,
                          authorization_reason],
                         Desired),
    maps:merge(Base#{id => PeerId}, Identity).

sanitize_template(Template) ->
    maps:with(allowed_template_keys(), Template).

allowed_dynamic_default_keys() ->
    [name,
     peer_module,
     mode,
     psk,
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
     debug_replay_controls,
     profile_id,
     certificate_fingerprint,
     enabled,
     revoked].

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
     profile_id,
     certificate_fingerprint].
