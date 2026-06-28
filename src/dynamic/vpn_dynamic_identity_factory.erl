%%%-------------------------------------------------------------------
%% @doc Development-only filesystem identity factory for dynamic allocations.
%%
%% The allocator owns transport metadata. This factory owns only local
%% development identity files. It returns file references and certificate
%% metadata, never PEM bodies or private-key contents. Production issuance
%% remains the responsibility of IAS/the configured CA workflow.
%%%-------------------------------------------------------------------
-module(vpn_dynamic_identity_factory).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").
-include_lib("kernel/include/file.hrl").

-export([ensure/1, lookup/1, release/1]).

-define(MANIFEST_VERSION, 1).

-spec ensure(map()) -> {ok, map()} | {error, term()}.
ensure(Allocation) when is_map(Allocation) ->
    case validate_allocation(Allocation) of
        ok ->
            AllocationId = maps:get(allocation_id, Allocation),
            with_lock(AllocationId,
                      fun() -> ensure_locked(Allocation) end);
        {error, _} = Error -> Error
    end;
ensure(_Allocation) ->
    {error, invalid_dynamic_allocation}.

-spec lookup(binary()) -> {ok, map()} | {error, term()}.
lookup(AllocationId) when is_binary(AllocationId), byte_size(AllocationId) > 0 ->
    case safe_identifier(AllocationId) of
        true ->
            with_config(
              fun(Config) ->
                  ManifestPath = manifest_path(AllocationId, Config),
                  case read_manifest_file(ManifestPath) of
                      {ok, Manifest} ->
                          case validate_manifest(Manifest) of
                              {ok, Allocation} ->
                                  Paths = paths(AllocationId,
                                                maps:get(client_peer_id, Allocation),
                                                maps:get(gateway_peer_id, Allocation),
                                                Config),
                                  validate_bundle(Allocation, Paths);
                              {error, _} = Error -> Error
                          end;
                      {error, _} = Error -> Error
                  end
              end);
        false -> {error, invalid_allocation_id}
    end;
lookup(_AllocationId) ->
    {error, invalid_allocation_id}.

-spec release(binary()) -> {ok, map()} | {error, term()}.
release(AllocationId) when is_binary(AllocationId), byte_size(AllocationId) > 0 ->
    case safe_identifier(AllocationId) of
        true ->
            with_lock(
              AllocationId,
              fun() ->
                  case lookup(AllocationId) of
                      {ok, Bundle} ->
                          case remove_tree(maps:get(bundle_dir, Bundle)) of
                              ok ->
                                  {ok, Bundle#{state => released,
                                               released_at => erlang:system_time(second)}};
                              {error, Reason} ->
                                  {error, {dynamic_identity_release_failed, Reason}}
                          end;
                      {error, _} = Error -> Error
                  end
              end);
        false -> {error, invalid_allocation_id}
    end;
release(_AllocationId) ->
    {error, invalid_allocation_id}.

ensure_locked(Allocation) ->
    with_config(
      fun(Config) ->
          AllocationId = maps:get(allocation_id, Allocation),
          ClientPeerId = maps:get(client_peer_id, Allocation),
          GatewayPeerId = maps:get(gateway_peer_id, Allocation),
          Paths = paths(AllocationId, ClientPeerId, GatewayPeerId, Config),
          case bundle_presence(Paths) of
              absent ->
                  create_and_validate(Allocation, Paths, Config);
              complete ->
                  validate_and_persist(Allocation, Paths);
              {partial, Missing} ->
                  {error, {incomplete_dynamic_identity_bundle,
                           AllocationId,
                           Missing}}
          end
      end).

create_and_validate(Allocation, Paths, Config) ->
    CommandModule = maps:get(command_module, Config),
    case CommandModule:ensure(Paths, Allocation, Config) of
        ok -> validate_and_persist(Allocation, Paths);
        {error, _} = Error -> Error;
        Other -> {error, {invalid_dynamic_identity_command_result, Other}}
    end.

validate_and_persist(Allocation, Paths) ->
    case existing_manifest_status(Allocation, Paths) of
        missing ->
            case validate_bundle(Allocation, Paths) of
                {ok, Bundle} ->
                    case write_manifest(Allocation, Paths) of
                        ok -> {ok, Bundle};
                        {error, Reason} ->
                            {error, {dynamic_identity_manifest_write_failed, Reason}}
                    end;
                {error, _} = Error -> Error
            end;
        present ->
            validate_bundle(Allocation, Paths);
        {error, _} = Error ->
            Error
    end.

existing_manifest_status(Allocation, Paths) ->
    Path = maps:get(manifest_path, Paths),
    case read_manifest_file(Path) of
        {ok, Manifest} ->
            case validate_manifest(Manifest) of
                {ok, ExistingAllocation} ->
                    case same_allocation_identity(Allocation, ExistingAllocation) of
                        true -> present;
                        false -> {error, dynamic_identity_manifest_allocation_mismatch}
                    end;
                {error, _} = Error -> Error
            end;
        {error, dynamic_identity_not_found} ->
            missing;
        {error, _} = Error ->
            Error
    end.

same_allocation_identity(Allocation, Existing) ->
    lists:all(fun(Key) -> maps:get(Key, Allocation) =:= maps:get(Key, Existing) end,
              [allocation_id, device_id, client_peer_id, gateway_peer_id]).

validate_bundle(Allocation, Paths) ->
    case regular_files(required_files(Paths)) of
        ok ->
            case private_key_permissions(Paths) of
                ok -> validate_client(Allocation, Paths);
                {error, _} = Error -> Error
            end;
        {error, _} = Error -> Error
    end.

validate_client(Allocation, Paths) ->
    ClientPeerId = maps:get(client_peer_id, Allocation),
    OvpnPath = maps:get(client_ovpn_path, Paths),
    case vpn_ovpn_identity:load(OvpnPath) of
        {ok, Identity} ->
            ExpectedKey = filename:absname(maps:get(client_private_key_path, Paths)),
            case {common_name(Identity),
                  maps:get(private_key_path, Identity, undefined)} of
                {ClientPeerId, ExpectedKey} ->
                    validate_client_certificate_file(Allocation, Paths, Identity);
                {OtherCn, _} when OtherCn =/= ClientPeerId ->
                    {error, {dynamic_client_certificate_subject_mismatch,
                             ClientPeerId,
                             OtherCn}};
                {_Cn, OtherKey} ->
                    {error, {dynamic_client_key_reference_mismatch,
                             ExpectedKey,
                             OtherKey}}
            end;
        {error, Reason} ->
            {error, {dynamic_client_identity_invalid, Reason}}
    end.

validate_client_certificate_file(Allocation, Paths, Identity) ->
    CertPath = maps:get(client_certificate_path, Paths),
    case certificate_info(CertPath) of
        {ok, ClientCert} ->
            ExpectedFingerprint = maps:get(certificate_fingerprint, Identity),
            FileCn = maps:get(common_name, ClientCert, undefined),
            FileFingerprint = maps:get(fingerprint, ClientCert),
            ExpectedCn = maps:get(client_peer_id, Allocation),
            case {FileCn =:= ExpectedCn,
                  FileFingerprint =:= ExpectedFingerprint} of
                {true, true} ->
                    validate_gateway(Allocation, Paths, Identity);
                _ ->
                    {error, {dynamic_client_certificate_file_mismatch,
                             ExpectedCn,
                             FileCn}}
            end;
        {error, Reason} ->
            {error, {dynamic_client_certificate_invalid, Reason}}
    end.

validate_gateway(Allocation, Paths, ClientIdentity) ->
    GatewayPeerId = maps:get(gateway_peer_id, Allocation),
    Config = #{id => GatewayPeerId,
               certificate_path => maps:get(gateway_certificate_path, Paths),
               private_key_path => maps:get(gateway_private_key_path, Paths),
               ca_certificate_path => maps:get(ca_certificate_path, Paths)},
    case vpn_identity:load(Config) of
        {ok, Identity} ->
            case common_name(Identity) of
                GatewayPeerId ->
                    build_bundle(Allocation, Paths, ClientIdentity, Identity);
                OtherCn ->
                    {error, {dynamic_gateway_certificate_subject_mismatch,
                             GatewayPeerId,
                             OtherCn}}
            end;
        {error, Reason} ->
            {error, {dynamic_gateway_identity_invalid, Reason}}
    end.

build_bundle(Allocation, Paths, ClientIdentity, GatewayIdentity) ->
    case certificate_info(maps:get(gateway_certificate_path, Paths)) of
        {ok, GatewayCert} ->
            ClientSafe = vpn_ovpn_identity:safe_info(ClientIdentity),
            GatewaySafe = vpn_identity:safe_info(GatewayIdentity),
            {ok,
             #{allocation_id => maps:get(allocation_id, Allocation),
               device_id => maps:get(device_id, Allocation),
               state => ready,
               mode => development,
               bundle_dir => maps:get(bundle_dir, Paths),
               ca_certificate_path => maps:get(ca_certificate_path, Paths),
               client => #{peer_id => maps:get(client_peer_id, Allocation),
                           ovpn_path => maps:get(client_ovpn_path, Paths),
                           certificate_path => maps:get(client_certificate_path, Paths),
                           private_key_path => maps:get(client_private_key_path, Paths),
                           ca_certificate_path => maps:get(ca_certificate_path, Paths),
                           certificate_fingerprint =>
                               maps:get(certificate_fingerprint, ClientSafe),
                           ca_fingerprint => maps:get(ca_fingerprint, ClientSafe),
                           identity_ready => true},
               gateway => #{peer_id => maps:get(gateway_peer_id, Allocation),
                            certificate_path => maps:get(gateway_certificate_path, Paths),
                            private_key_path => maps:get(gateway_private_key_path, Paths),
                            ca_certificate_path => maps:get(ca_certificate_path, Paths),
                            certificate_fingerprint => maps:get(fingerprint, GatewayCert),
                            trusted => maps:get(trusted, GatewaySafe),
                            key_match => maps:get(key_match, GatewaySafe)}}};
        {error, Reason} ->
            {error, {dynamic_gateway_certificate_invalid, Reason}}
    end.

with_config(Fun) ->
    case load_config() of
        {ok, Config} -> Fun(Config);
        {error, _} = Error -> Error
    end.

load_config() ->
    Defaults = #{mode => disabled,
                 root_dir => "local/dynamic",
                 ca_dir => "local/ca",
                 tool_path => "tools/ensure-dynamic-identity.sh",
                 command_module => vpn_dynamic_identity_command},
    case application:get_env(vpn, dynamic_identity_factory, #{}) of
        User when is_map(User) ->
            validate_config(maps:merge(Defaults, User));
        _ ->
            {error, invalid_dynamic_identity_factory_config}
    end.

validate_config(Config) ->
    Mode0 = maps:get(mode, Config),
    Mode = case Mode0 of
               <<"development">> -> development;
               Value -> Value
           end,
    case Mode of
        development ->
            case valid_relative_path(maps:get(root_dir, Config)) andalso
                 valid_relative_path(maps:get(ca_dir, Config)) andalso
                 valid_tool_path(maps:get(tool_path, Config)) andalso
                 is_atom(maps:get(command_module, Config)) of
                true -> {ok, Config#{mode => development}};
                false -> {error, invalid_dynamic_identity_factory_config}
            end;
        _ ->
            {error, dynamic_identity_factory_disabled}
    end.

manifest_path(AllocationId, Config) ->
    filename:join([maps:get(root_dir, Config),
                   binary_to_list(AllocationId),
                   "identity.manifest"]).

paths(AllocationId, ClientPeerId, GatewayPeerId, Config) ->
    BundleDir = filename:join(maps:get(root_dir, Config), binary_to_list(AllocationId)),
    ManifestPath = filename:join(BundleDir, "identity.manifest"),
    ClientName = binary_to_list(ClientPeerId),
    GatewayName = binary_to_list(GatewayPeerId),
    #{bundle_dir => BundleDir,
      ca_dir => maps:get(ca_dir, Config),
      manifest_path => ManifestPath,
      ca_certificate_path => filename:join(maps:get(ca_dir, Config), "ca.crt"),
      client_ovpn_path => filename:join(BundleDir, ClientName ++ ".ovpn"),
      client_certificate_path => filename:join([BundleDir, "certs", ClientName ++ ".crt"]),
      client_private_key_path => filename:join([BundleDir, "keys", ClientName ++ ".key"]),
      client_csr_path => filename:join([BundleDir, "csr", ClientName ++ ".csr"]),
      gateway_certificate_path => filename:join([BundleDir, "certs", GatewayName ++ ".crt"]),
      gateway_private_key_path => filename:join([BundleDir, "keys", GatewayName ++ ".key"]),
      gateway_csr_path => filename:join([BundleDir, "csr", GatewayName ++ ".csr"])}.

bundle_presence(Paths) ->
    Required = bundle_files(Paths),
    Existing = [Path || Path <- Required, filelib:is_file(Path)],
    case length(Existing) of
        0 -> absent;
        Count when Count =:= length(Required) -> complete;
        _ -> {partial, Required -- Existing}
    end.

bundle_files(Paths) ->
    [maps:get(client_ovpn_path, Paths),
     maps:get(client_certificate_path, Paths),
     maps:get(client_private_key_path, Paths),
     maps:get(client_csr_path, Paths),
     maps:get(gateway_certificate_path, Paths),
     maps:get(gateway_private_key_path, Paths),
     maps:get(gateway_csr_path, Paths)].

required_files(Paths) ->
    bundle_files(Paths) ++ [maps:get(ca_certificate_path, Paths)].

regular_files([]) -> ok;
regular_files([Path | Rest]) ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = regular}} -> regular_files(Rest);
        {ok, #file_info{type = symlink}} -> {error, {dynamic_identity_symlink_forbidden, Path}};
        {ok, _} -> {error, {dynamic_identity_file_not_regular, Path}};
        {error, Reason} -> {error, {dynamic_identity_file_missing, Path, Reason}}
    end.


private_key_permissions([]) -> ok;
private_key_permissions([Path | Rest]) ->
    case file:read_file_info(Path) of
        {ok, #file_info{mode = Mode}} when Mode band 8#077 =:= 0 ->
            private_key_permissions(Rest);
        {ok, _Info} ->
            {error, {insecure_dynamic_private_key_permissions, Path}};
        {error, Reason} ->
            {error, {dynamic_private_key_info_failed, Path, Reason}}
    end;
private_key_permissions(Paths) ->
    private_key_permissions([maps:get(client_private_key_path, Paths),
        maps:get(gateway_private_key_path, Paths)]).

write_manifest(Allocation, Paths) ->
    Manifest = #{version => ?MANIFEST_VERSION,
                 allocation_id => maps:get(allocation_id, Allocation),
                 device_id => maps:get(device_id, Allocation),
                 client_peer_id => maps:get(client_peer_id, Allocation),
                 gateway_peer_id => maps:get(gateway_peer_id, Allocation),
                 created_at => erlang:system_time(second)},
    Path = maps:get(manifest_path, Paths),
    ok = filelib:ensure_dir(Path),
    Temp = Path ++ ".tmp",
    case file:write_file(Temp, term_to_binary(Manifest, [compressed])) of
        ok -> file:rename(Temp, Path);
        {error, _} = Error -> Error
    end.

read_manifest_file(Path) ->
    case file:read_file(Path) of
        {ok, Binary} ->
            try {ok, binary_to_term(Binary, [safe])}
            catch _:_ -> {error, invalid_dynamic_identity_manifest}
            end;
        {error, enoent} -> {error, dynamic_identity_not_found};
        {error, Reason} -> {error, {dynamic_identity_manifest_read_failed, Reason}}
    end.

validate_manifest(#{version := ?MANIFEST_VERSION,
                    allocation_id := AllocationId,
                    device_id := DeviceId,
                    client_peer_id := ClientPeerId,
                    gateway_peer_id := GatewayPeerId}) ->
    Allocation = #{allocation_id => AllocationId,
                   device_id => DeviceId,
                   client_peer_id => ClientPeerId,
                   gateway_peer_id => GatewayPeerId},
    case validate_manifest_values(Allocation) of
        ok -> {ok, Allocation};
        {error, _} = Error -> Error
    end;
validate_manifest(_Manifest) ->
    {error, invalid_dynamic_identity_manifest}.

validate_manifest_values(Allocation) ->
    case validate_binary_id(maps:get(allocation_id, Allocation)) andalso
         nonempty_binary(maps:get(device_id, Allocation)) andalso
         validate_binary_id(maps:get(client_peer_id, Allocation)) andalso
         validate_binary_id(maps:get(gateway_peer_id, Allocation)) of
        true -> ok;
        false -> {error, invalid_dynamic_identity_manifest}
    end.

validate_allocation(Allocation) ->
    Required = [allocation_id, device_id, client_peer_id, gateway_peer_id,
                client, gateway],
    case [Key || Key <- Required, not maps:is_key(Key, Allocation)] of
        [] ->
            Client = maps:get(client, Allocation),
            Gateway = maps:get(gateway, Allocation),
            case validate_binary_id(maps:get(allocation_id, Allocation)) andalso
                 nonempty_binary(maps:get(device_id, Allocation)) andalso
                 validate_binary_id(maps:get(client_peer_id, Allocation)) andalso
                 validate_binary_id(maps:get(gateway_peer_id, Allocation)) andalso
                 is_map(Client) andalso is_map(Gateway) andalso
                 valid_remote(maps:get(remote_ip, Client, undefined)) andalso
                 valid_port(maps:get(local_udp_port, Gateway, undefined)) of
                true -> ok;
                false -> {error, invalid_dynamic_allocation}
            end;
        [Missing | _] ->
            {error, {missing_dynamic_allocation_key, Missing}}
    end.

validate_binary_id(Value) ->
    nonempty_binary(Value) andalso safe_identifier(Value).

nonempty_binary(Value) ->
    is_binary(Value) andalso byte_size(Value) > 0.

safe_identifier(Binary) ->
    lists:all(fun safe_identifier_char/1, binary_to_list(Binary)).

safe_identifier_char(Char) when Char >= $a, Char =< $z -> true;
safe_identifier_char(Char) when Char >= $A, Char =< $Z -> true;
safe_identifier_char(Char) when Char >= $0, Char =< $9 -> true;
safe_identifier_char($_) -> true;
safe_identifier_char($-) -> true;
safe_identifier_char($.) -> true;
safe_identifier_char(_) -> false.

valid_remote({A, B, C, D}) ->
    lists:all(fun(N) -> is_integer(N) andalso N >= 0 andalso N =< 255 end,
              [A, B, C, D]);
valid_remote(Value) when is_binary(Value); is_list(Value) -> true;
valid_remote(_) -> false.

valid_port(Port) -> is_integer(Port) andalso Port > 0 andalso Port =< 65535.

valid_relative_path(Path) when is_binary(Path) -> valid_relative_path(binary_to_list(Path));
valid_relative_path(Path) when is_list(Path), Path =/= [] ->
    filename:pathtype(Path) =:= relative andalso
    not lists:member("..", filename:split(Path)) andalso
    not lists:member(".", filename:split(Path));
valid_relative_path(_) -> false.

valid_tool_path(Path) when is_binary(Path) -> valid_tool_path(binary_to_list(Path));
valid_tool_path(Path) when is_list(Path), Path =/= [] -> true;
valid_tool_path(_) -> false.

certificate_info(Path) ->
    case file:read_file(Path) of
        {ok, Pem} ->
            try
                case public_key:pem_decode(Pem) of
                    [{_, Der, _}] ->
                        Cert = public_key:pkix_decode_cert(Der, otp),
                        {ok, #{fingerprint => hex(crypto:hash(sha256, Der)),
                               common_name => certificate_common_name(Cert)}};
                    _ -> {error, invalid_certificate_pem}
                end
            catch Class:Reason -> {error, {Class, Reason}}
            end;
        {error, Reason} -> {error, {certificate_read_failed, Path, Reason}}
    end.

common_name(#{certificate := #{subject := Subject}}) -> subject_common_name(Subject);
common_name(_Identity) -> undefined.

certificate_common_name(#'OTPCertificate'{tbsCertificate =
                                            #'OTPTBSCertificate'{subject = Subject}}) ->
    subject_common_name(Subject);
certificate_common_name(_) -> undefined.

subject_common_name({rdnSequence, Rdns}) ->
    find_common_name(Rdns);
subject_common_name(_) -> undefined.

find_common_name([]) -> undefined;
find_common_name([Rdn | Rest]) ->
    case find_common_name_in_rdn(Rdn) of
        undefined -> find_common_name(Rest);
        Value -> Value
    end.

find_common_name_in_rdn([]) -> undefined;
find_common_name_in_rdn([{'AttributeTypeAndValue', {2,5,4,3}, Value} | _]) ->
    directory_string(Value);
find_common_name_in_rdn([_ | Rest]) -> find_common_name_in_rdn(Rest);
find_common_name_in_rdn(_) -> undefined.

directory_string({_Type, Value}) when is_binary(Value) -> Value;
directory_string({_Type, Value}) when is_list(Value) -> unicode:characters_to_binary(Value);
directory_string(Value) when is_binary(Value) -> Value;
directory_string(Value) when is_list(Value) -> unicode:characters_to_binary(Value);
directory_string(_) -> undefined.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

with_lock(_AllocationId, Fun) ->
    %% The development CA serial file is shared by all allocations, so identity
    %% creation and release are serialized across the node rather than only per
    %% allocation.
    case global:trans({?MODULE, dynamic_identity_factory}, Fun, [node()]) of
        aborted -> {error, dynamic_identity_lock_aborted};
        Result -> Result
    end.

remove_tree(Path) ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = directory}} ->
            case file:list_dir(Path) of
                {ok, Entries} ->
                    case remove_children(Path, Entries) of
                        ok -> file:del_dir(Path);
                        {error, _} = Error -> Error
                    end;
                {error, Reason} -> {error, Reason}
            end;
        {ok, #file_info{type = symlink}} -> file:delete(Path);
        {ok, _} -> file:delete(Path);
        {error, enoent} -> ok;
        {error, Reason} -> {error, Reason}
    end.

remove_children(_Path, []) -> ok;
remove_children(Path, [Entry | Rest]) ->
    case remove_tree(filename:join(Path, Entry)) of
        ok -> remove_children(Path, Rest);
        {error, _} = Error -> Error
    end.
