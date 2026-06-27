%%%-------------------------------------------------------------------
%% @doc Validation boundary for secret-free IAS recovery manifests.
%%%-------------------------------------------------------------------
-module(vpn_recovery_manifest).

-export([validate/1,
         summary/1]).

-define(SCHEMA_VERSION, 1).

validate(#{schema_version := ?SCHEMA_VERSION,
           device := #{kind := device, id := DeviceId},
           certificate := #{kind := certificate, id := CertificateId},
           vpn_service := #{kind := vpn_service, id := ServiceId},
           objects := Objects,
           relationships := Relationships} = Manifest)
  when is_list(Objects), is_list(Relationships) ->
    Device = maps:get(device, Manifest),
    Certificate = maps:get(certificate, Manifest),
    Service = maps:get(vpn_service, Manifest),
    case usable_id(DeviceId) andalso usable_id(CertificateId)
         andalso usable_id(ServiceId)
         andalso valid_object(Device)
         andalso valid_object(Certificate)
         andalso valid_certificate_object(Certificate)
         andalso valid_object(Service)
         andalso lists:all(fun valid_object/1, Objects)
         andalso unique_object_identities(Objects)
         andalso lists:member(Device, Objects)
         andalso lists:member(Certificate, Objects)
         andalso lists:member(Service, Objects)
         andalso lists:all(fun valid_relationship/1, Relationships)
         andalso relationship_endpoints_present(Relationships, Objects)
         andalso required_relationship(DeviceId, CertificateId,
                                        certificate, Relationships)
         andalso required_relationship(DeviceId, ServiceId,
                                        vpn_service, Relationships)
         andalso forbidden_path(Manifest) =:= none of
        true -> ok;
        false -> {error, invalid_recovery_manifest}
    end;
validate(#{schema_version := Version}) ->
    {error, {unsupported_recovery_manifest_schema_version, Version}};
validate(_) ->
    {error, invalid_recovery_manifest}.

summary(Manifest) ->
    case validate(Manifest) of
        ok ->
            #{schema_version => ?SCHEMA_VERSION,
              provisioning_transaction_id =>
                  maps:get(provisioning_transaction_id, Manifest, undefined),
              wizard_id => maps:get(wizard_id, Manifest, undefined),
              device_id => maps:get(id, maps:get(device, Manifest)),
              certificate_id => maps:get(id, maps:get(certificate, Manifest)),
              vpn_service_id => maps:get(id, maps:get(vpn_service, Manifest)),
              object_count => length(maps:get(objects, Manifest)),
              relationship_count => length(maps:get(relationships, Manifest))};
        {error, Reason} ->
            #{invalid => true, reason => Reason}
    end.

valid_object(#{id := Id, kind := Kind} = Object) ->
    usable_id(Id) andalso allowed_kind(Kind)
        andalso forbidden_path(Object) =:= none;
valid_object(_) -> false.

valid_certificate_object(Certificate) ->
    usable_id(maps:get(fingerprint_sha256, Certificate, undefined)).

valid_relationship(#{relation_type := RelationType,
                     source_kind := SourceKind,
                     source_id := SourceId,
                     target_kind := TargetKind,
                     target_id := TargetId} = Relationship) ->
    RelationType =/= undefined andalso allowed_kind(SourceKind)
        andalso allowed_kind(TargetKind) andalso usable_id(SourceId)
        andalso usable_id(TargetId)
        andalso forbidden_path(Relationship) =:= none;
valid_relationship(_) -> false.

unique_object_identities(Objects) ->
    Identities = [{maps:get(kind, Object),
                   normalize_id(maps:get(id, Object))}
                  || Object <- Objects],
    length(Identities) =:= length(lists:usort(Identities)).

relationship_endpoints_present(Relationships, Objects) ->
    lists:all(
      fun(Relationship) ->
          object_identity_present(maps:get(source_kind, Relationship),
                                  maps:get(source_id, Relationship),
                                  Objects)
              andalso
          object_identity_present(maps:get(target_kind, Relationship),
                                  maps:get(target_id, Relationship),
                                  Objects)
      end,
      Relationships).

object_identity_present(Kind, Id, Objects) ->
    lists:any(fun(Object) ->
                      maps:get(kind, Object) =:= Kind andalso
                      normalize_id(maps:get(id, Object)) =:= normalize_id(Id)
              end,
              Objects).

required_relationship(DeviceId, TargetId, TargetKind, Relationships) ->
    lists:any(
      fun(Relationship) ->
          maps:get(source_kind, Relationship) =:= device andalso
          normalize_id(maps:get(source_id, Relationship)) =:=
              normalize_id(DeviceId) andalso
          maps:get(target_kind, Relationship) =:= TargetKind andalso
          normalize_id(maps:get(target_id, Relationship)) =:=
              normalize_id(TargetId) andalso
          required_relation_type(TargetKind,
                                 maps:get(relation_type, Relationship))
      end,
      Relationships).

required_relation_type(certificate, uses_certificate) -> true;
required_relation_type(vpn_service, uses_service) -> true;
required_relation_type(vpn_service, uses_vpn_service) -> true;
required_relation_type(_, _) -> false.

allowed_kind(device) -> true;
allowed_kind(certificate) -> true;
allowed_kind(vpn_service) -> true;
allowed_kind(security_profile) -> true;
allowed_kind(security_policy) -> true;
allowed_kind(user) -> true;
allowed_kind(_) -> false.

forbidden_path(Map) when is_map(Map) ->
    forbidden_pairs(maps:to_list(Map));
forbidden_path(List) when is_list(List) ->
    forbidden_values(List);
forbidden_path(Tuple) when is_tuple(Tuple) ->
    forbidden_values(tuple_to_list(Tuple));
forbidden_path(Binary) when is_binary(Binary) ->
    case binary:match(Binary, <<"-----BEGIN ">>) of
        nomatch -> none;
        _ -> pem_material
    end;
forbidden_path(Value) when is_pid(Value); is_port(Value); is_reference(Value);
                           is_function(Value) ->
    unsafe_term;
forbidden_path(_) -> none.

forbidden_pairs([]) -> none;
forbidden_pairs([{Key, Value} | Rest]) ->
    case forbidden_key(Key) of
        true -> Key;
        false ->
            case forbidden_path(Value) of
                none -> forbidden_pairs(Rest);
                Found -> Found
            end
    end.

forbidden_values([]) -> none;
forbidden_values([Value | Rest]) ->
    case forbidden_path(Value) of
        none -> forbidden_values(Rest);
        Found -> Found
    end.

forbidden_key(Key) ->
    Text = string:lowercase(binary_to_list(text(Key))),
    lists:any(fun(Fragment) -> string:find(Text, Fragment) =/= nomatch end,
              ["private_key", "privatekey", "key_pem", "pem_body",
               "certificate_body", "certificate_pem", "certificate_der",
               "cert_pem", "ca_body", "ca_pem", "csr_body", "csr_pem",
               "cmp_body", "raw_cmp", "ovpn", "password", "passphrase",
               "shared_secret", "session_key", "psk", "tls_auth"]).

usable_id(Value) when is_binary(Value) -> byte_size(Value) > 0;
usable_id(Value) when is_atom(Value) -> Value =/= undefined;
usable_id(_) -> false.

normalize_id(Value) -> text(Value).

text(Value) when is_binary(Value) -> Value;
text(Value) when is_atom(Value) -> atom_to_binary(Value, utf8);
text(Value) when is_list(Value) -> unicode:characters_to_binary(Value);
text(Value) -> unicode:characters_to_binary(io_lib:format("~p", [Value])).
