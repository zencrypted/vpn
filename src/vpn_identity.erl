%%%-------------------------------------------------------------------
%% @doc Certificate identity metadata loader.
%%%-------------------------------------------------------------------
-module(vpn_identity).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").

-export([load/1, safe_info/1]).

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
    case file:read_file(CertPath) of
        {ok, CertPem} ->
            load_key(Config, CertPath, KeyPath, CertPem);
        {error, Reason} ->
            {error, {certificate_read_failed, CertPath, Reason}}
    end.

load_key(Config, CertPath, KeyPath, CertPem) ->
    case parse_certificate(CertPem) of
        {ok, Certificate} ->
            load_key(Config, CertPath, KeyPath, CertPem, Certificate);
        {error, Reason} ->
            {error, {certificate_parse_failed, CertPath, Reason}}
    end.

load_key(Config, CertPath, KeyPath, CertPem, Certificate) ->
    case file:read_file(KeyPath) of
        {ok, KeyPem} ->
            {ok, #{peer_id => maps:get(id, Config),
                   certificate_path => CertPath,
                   private_key_path => KeyPath,
                   certificate_pem => CertPem,
                   private_key_pem => KeyPem,
                   certificate => Certificate}};
        {error, Reason} ->
            {error, {private_key_read_failed, KeyPath, Reason}}
    end.

parse_certificate(CertPem) ->
    try
        case public_key:pem_decode(CertPem) of
            [Entry | _] ->
                certificate_metadata(public_key:pem_entry_decode(Entry));
            [] ->
                {error, no_pem_entry}
        end
    catch
        Class:Reason ->
            {error, {Class, Reason}}
    end.

certificate_metadata(#'Certificate'{tbsCertificate = Tbs}) ->
    #'TBSCertificate'{issuer = Issuer,
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

required_identity_key(Config) ->
    required_identity_key(Config, [certificate_path, private_key_path]).

required_identity_key(_Config, []) ->
    none;
required_identity_key(Config, [Key | Rest]) ->
    case maps:is_key(Key, Config) of
        true ->
            required_identity_key(Config, Rest);
        false ->
            {missing, Key}
    end.
