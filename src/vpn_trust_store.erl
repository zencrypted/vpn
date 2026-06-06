%%%-------------------------------------------------------------------
%% @doc Development certificate trust store.
%%%-------------------------------------------------------------------
-module(vpn_trust_store).

-export([load/1, verify/2]).

load(CaPath) ->
    case file:read_file(CaPath) of
        {ok, CaPem} ->
            load_pem(CaPath, CaPem);
        {error, Reason} ->
            {error, {ca_certificate_read_failed, CaPath, Reason}}
    end.

verify(#{ca_certificate := CaCertificate}, Certificate) ->
    case public_key:pkix_is_self_signed(Certificate) of
        true ->
            {error, self_signed_certificate};
        false ->
            verify_issuer(CaCertificate, Certificate)
    end;
verify(_TrustStore, _Certificate) ->
    {error, invalid_trust_store}.

load_pem(CaPath, CaPem) ->
    try
        case public_key:pem_decode(CaPem) of
            [{_, Der, _} | _] ->
                {ok, #{ca_path => CaPath,
                       ca_pem => CaPem,
                       ca_certificate => public_key:pkix_decode_cert(Der, otp)}};
            [] ->
                {error, no_pem_entry}
        end
    catch
        Class:Reason ->
            {error, {ca_certificate_parse_failed, CaPath, {Class, Reason}}}
    end.

verify_issuer(CaCertificate, Certificate) ->
    case public_key:pkix_is_issuer(Certificate, CaCertificate) of
        true ->
            verify_path(CaCertificate, Certificate);
        false ->
            {error, issuer_mismatch}
    end.

verify_path(CaCertificate, Certificate) ->
    case public_key:pkix_path_validation(CaCertificate, [Certificate], []) of
        {ok, _} ->
            ok;
        {error, Reason} ->
            {error, {signature_verification_failed, Reason}}
    end.
