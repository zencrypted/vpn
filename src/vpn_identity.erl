%%%-------------------------------------------------------------------
%% @doc Certificate identity metadata loader.
%%%-------------------------------------------------------------------
-module(vpn_identity).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").

-export([load/1, safe_info/1, verify_key_match/1]).

load(Config) when is_map(Config) ->
    case required_identity_key(Config) of
        none ->
            load_files(Config);
        {missing, Key} ->
            {error, {missing_identity_key, Key}}
    end;
load(_Config) ->
    {error, invalid_config}.

safe_info(Identity) ->
    maps:with([peer_id, certificate_path, private_key_path, certificate], Identity).

load_files(Config) ->
    CertPath = maps:get(certificate_path, Config),
    KeyPath = maps:get(private_key_path, Config),
    CaPath = maps:get(ca_certificate_path, Config),
    case file:read_file(CertPath) of
        {ok, CertPem} ->
            load_key(Config, CertPath, KeyPath, CaPath, CertPem);
        {error, Reason} ->
            {error, {certificate_read_failed, CertPath, Reason}}
    end.

load_key(Config, CertPath, KeyPath, CaPath, CertPem) ->
    case parse_certificate(CertPem) of
        {ok, Certificate, CertificateMetadata} ->
            verify_certificate(Config,
                               CertPath,
                               KeyPath,
                               CaPath,
                               CertPem,
                               Certificate,
                               CertificateMetadata);
        {error, Reason} ->
            {error, {certificate_parse_failed, CertPath, Reason}}
    end.

verify_certificate(Config,
                   CertPath,
                   KeyPath,
                   CaPath,
                   CertPem,
                   Certificate,
                   CertificateMetadata) ->
    case vpn_trust_store:load(CaPath) of
        {ok, TrustStore} ->
            case vpn_trust_store:verify(TrustStore, Certificate) of
                ok ->
                    load_key(Config,
                             CertPath,
                             KeyPath,
                             CaPath,
                             CertPem,
                             Certificate,
                             CertificateMetadata);
                {error, Reason} ->
                    {error, {certificate_verification_failed, CertPath, Reason}}
            end;
        {error, Reason} ->
            {error, {ca_certificate_load_failed, CaPath, Reason}}
    end.

load_key(Config,
         CertPath,
         KeyPath,
         CaPath,
         CertPem,
         Certificate,
         CertificateMetadata) ->
    case file:read_file(KeyPath) of
        {ok, KeyPem} ->
            load_private_key(Config,
                             CertPath,
                             KeyPath,
                             CaPath,
                             CertPem,
                             Certificate,
                             CertificateMetadata,
                             KeyPem);
        {error, Reason} ->
            {error, {private_key_read_failed, KeyPath, Reason}}
    end.

load_private_key(Config,
                 CertPath,
                 KeyPath,
                 CaPath,
                 CertPem,
                 Certificate,
                 CertificateMetadata,
                 KeyPem) ->
    case parse_private_key_public_part(KeyPem) of
        {ok, PrivateKeyPublicPart} ->
            Identity = #{peer_id => maps:get(id, Config),
                         certificate_path => CertPath,
                         private_key_path => KeyPath,
                         ca_certificate_path => CaPath,
                         certificate_pem => CertPem,
                         private_key_pem => KeyPem,
                         x509_certificate => Certificate,
                         private_key_public_part => PrivateKeyPublicPart,
                         certificate => CertificateMetadata},
            case verify_key_match(Identity) of
                ok ->
                    {ok, Identity};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, {private_key_parse_failed, KeyPath, Reason}}
    end.

verify_key_match(#{x509_certificate := Certificate,
                   private_key_public_part := PrivateKeyPublicPart}) ->
    case certificate_public_key(Certificate) of
        {ok, PrivateKeyPublicPart} ->
            ok;
        {ok, _CertificatePublicKey} ->
            {error, key_mismatch};
        {error, Reason} ->
            {error, Reason}
    end.

parse_certificate(CertPem) ->
    try
        case public_key:pem_decode(CertPem) of
            [{_, Der, _} | _] ->
                Certificate = public_key:pkix_decode_cert(Der, otp),
                case certificate_metadata(Certificate) of
                    {ok, Metadata} ->
                        {ok, Certificate, Metadata};
                    {error, MetadataReason} ->
                        {error, MetadataReason}
                end;
            [] ->
                {error, no_pem_entry}
        end
    catch
        Class:ParseReason ->
            {error, {Class, ParseReason}}
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

parse_private_key_public_part(KeyPem) ->
    try
        case public_key:pem_decode(KeyPem) of
            [Entry | _] ->
                private_key_public_part(public_key:pem_entry_decode(Entry));
            [] ->
                {error, no_pem_entry}
        end
    catch
        Class:ParseReason ->
            {error, {Class, ParseReason}}
    end.

certificate_public_key(#'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{
                                           subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
                                             subjectPublicKey = PublicKey}}}) ->
    {ok, PublicKey};
certificate_public_key(_Certificate) ->
    {error, unsupported_certificate_key}.

private_key_public_part(#'RSAPrivateKey'{modulus = Modulus,
                                         publicExponent = PublicExponent}) ->
    {ok, #'RSAPublicKey'{modulus = Modulus,
                         publicExponent = PublicExponent}};
private_key_public_part(_PrivateKey) ->
    {error, unsupported_private_key}.

required_identity_key(Config) ->
    required_identity_key(Config, [certificate_path, private_key_path, ca_certificate_path]).

required_identity_key(_Config, []) ->
    none;
required_identity_key(Config, [Key | Rest]) ->
    case maps:is_key(Key, Config) of
        true ->
            required_identity_key(Config, Rest);
        false ->
            {missing, Key}
    end.
