%%%-------------------------------------------------------------------
%% @doc Local identity validation for a canonical OVPN envelope.
%%
%% The private-key reference is resolved relative to the envelope file.
%% The private key is never returned, logged, copied, or embedded.
%%%-------------------------------------------------------------------
-module(vpn_ovpn_identity).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").
-include_lib("kernel/include/file.hrl").

-export([load/1, safe_info/1]).

-spec load(file:filename_all()) -> {ok, map()} | {error, term()}.
load(OvpnPath0) ->
    OvpnPath = filename:absname(filename_to_list(OvpnPath0)),
    case vpn_ovpn_parser:parse_file(OvpnPath) of
        {ok, Config} ->
            validate_config(OvpnPath, Config);
        {error, Reason} ->
            {error, {ovpn_parse_failed, Reason}}
    end.

-spec safe_info(map()) -> map().
safe_info(Identity) ->
    maps:with([ovpn_path,
               private_key_path,
               certificate_fingerprint,
               ca_fingerprint,
               certificate,
               trusted,
               key_match,
               identity_ready],
              Identity).

validate_config(OvpnPath, Config) ->
    case resolve_private_key_path(OvpnPath, maps:get(private_key_ref, Config)) of
        {ok, PrivateKeyPath} ->
            validate_private_key_file(OvpnPath, PrivateKeyPath, Config);
        {error, _} = Error ->
            Error
    end.

resolve_private_key_path(OvpnPath, PrivateKeyRef) when is_binary(PrivateKeyRef) ->
    Root = filename:dirname(OvpnPath),
    Candidate = filename:absname(filename:join(Root, binary_to_list(PrivateKeyRef))),
    case path_is_beneath(Root, Candidate) of
        true -> {ok, Candidate};
        false -> {error, private_key_path_escape}
    end.

path_is_beneath(Root0, Candidate0) ->
    Root = filename:split(filename:absname(Root0)),
    Candidate = filename:split(filename:absname(Candidate0)),
    lists:prefix(Root, Candidate) andalso length(Candidate) > length(Root).

validate_private_key_file(OvpnPath, PrivateKeyPath, Config) ->
    case file:read_link_info(PrivateKeyPath) of
        {ok, #file_info{type = regular, mode = Mode}} when Mode band 8#077 =:= 0 ->
            validate_materials(OvpnPath, PrivateKeyPath, Config);
        {ok, #file_info{type = regular}} ->
            {error, insecure_private_key_permissions};
        {ok, #file_info{type = symlink}} ->
            {error, private_key_symlink_forbidden};
        {ok, _Info} ->
            {error, private_key_not_regular_file};
        {error, Reason} ->
            {error, {private_key_read_failed, PrivateKeyPath, Reason}}
    end.

validate_materials(OvpnPath, PrivateKeyPath, Config) ->
    CaPem = maps:get(ca_pem, Config),
    CertPem = maps:get(certificate_pem, Config),
    case decode_certificate(CaPem) of
        {ok, _CaCert, CaDer} ->
            validate_client_certificate(OvpnPath,
                                        PrivateKeyPath,
                                        Config,
                                        CaPem,
                                        CaDer,
                                        CertPem);
        {error, Reason} ->
            {error, {ca_certificate_parse_failed, Reason}}
    end.

validate_client_certificate(OvpnPath,
                            PrivateKeyPath,
                            Config,
                            CaPem,
                            CaDer,
                            CertPem) ->
    case decode_certificate(CertPem) of
        {ok, Cert, CertDer} ->
            case certificate_metadata(Cert) of
                {ok, Certificate} ->
                    case verify_certificate(CaPem, Cert) of
                ok ->
                        verify_key_match(OvpnPath,
                                         PrivateKeyPath,
                                         Config,
                                         CertPem,
                                         CaDer,
                                         CertDer,
                                         Certificate);
                    {error, Reason} ->
                        {error, {certificate_verification_failed, Reason}}
                    end;
                {error, Reason} ->
                    {error, {certificate_metadata_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {certificate_parse_failed, Reason}}
    end.

verify_certificate(CaPem, Cert) ->
    case vpn_trust_store:load_pem(CaPem) of
        {ok, TrustStore} -> vpn_trust_store:verify(TrustStore, Cert);
        {error, Reason} -> {error, Reason}
    end.

verify_key_match(OvpnPath, PrivateKeyPath, Config, CertPem, CaDer, CertDer, Certificate) ->
    case vpn_identity:verify_pem_key_match(CertPem, PrivateKeyPath) of
        ok ->
            {ok, #{config => Config,
                   ovpn_path => OvpnPath,
                   private_key_path => PrivateKeyPath,
                   certificate_pem => CertPem,
                   ca_certificate_pem => maps:get(ca_pem, Config),
                   certificate_fingerprint => fingerprint(CertDer),
                   ca_fingerprint => fingerprint(CaDer),
                   certificate => Certificate,
                   trusted => true,
                   key_match => true,
                   identity_ready => true}};
        {error, Reason} ->
            {error, Reason}
    end.

decode_certificate(Pem) ->
    try
        case public_key:pem_decode(Pem) of
            [{'Certificate', Der, not_encrypted}] ->
                {ok, public_key:pkix_decode_cert(Der, otp), Der};
            [{_, Der, _}] ->
                {ok, public_key:pkix_decode_cert(Der, otp), Der};
            [] ->
                {error, no_pem_entry};
            _ ->
                {error, multiple_pem_entries}
        end
    catch
        Class:Reason -> {error, {Class, Reason}}
    end.

certificate_metadata(#'OTPCertificate'{tbsCertificate = Tbs}) ->
    #'OTPTBSCertificate'{issuer = Issuer,
                         serialNumber = SerialNumber,
                         subject = Subject,
                         validity = #'Validity'{notBefore = NotBefore,
                                                notAfter = NotAfter}} = Tbs,
    {ok, #{subject => Subject,
           issuer => Issuer,
           serial_number => SerialNumber,
           not_before => NotBefore,
           not_after => NotAfter}};
certificate_metadata(_Certificate) ->
    {error, invalid_certificate}.

fingerprint(Der) ->
    hex(crypto:hash(sha256, Der)).

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

filename_to_list(Path) when is_binary(Path) -> binary_to_list(Path);
filename_to_list(Path) when is_list(Path) -> Path.
