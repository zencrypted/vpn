%%%-------------------------------------------------------------------
%% @doc Certificate proof helpers for the VPN control-plane handshake.
%%
%% OpenSSL is used deliberately here because the project currently accepts
%% both RSA and EC private-key encodings and already depends on OpenSSL for
%% local OVPN key matching. Private-key bytes never enter handshake frames.
%%%-------------------------------------------------------------------
-module(vpn_handshake_auth).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").

-export([certificate_der/1, proof_data/9, sign/2, verify/5]).

certificate_der(CertificatePem) when is_binary(CertificatePem) ->
    try
        case public_key:pem_decode(CertificatePem) of
            [{'Certificate', Der, not_encrypted}] -> {ok, Der};
            [{_, Der, _}] -> {ok, Der};
            [] -> {error, no_pem_entry};
            _ -> {error, multiple_pem_entries}
        end
    catch
        Class:Reason -> {error, {certificate_parse_failed, {Class, Reason}}}
    end;
certificate_der(_) ->
    {error, invalid_certificate_pem}.

proof_data(SenderPeerId, ReceiverPeerId,
           SenderSessionId, ReceiverSessionId,
           SenderNonce, ReceiverNonce,
           SenderEphemeralPublicKey, ReceiverEphemeralPublicKey,
           CertificateDer) ->
    Sender = peer_id(SenderPeerId),
    Receiver = peer_id(ReceiverPeerId),
    crypto:hash(sha256,
                [<<"vpn-certificate-proof-v2">>,
                 length_prefixed(Sender), length_prefixed(Receiver),
                 SenderSessionId, ReceiverSessionId,
                 SenderNonce, ReceiverNonce,
                 length_prefixed(SenderEphemeralPublicKey),
                 length_prefixed(ReceiverEphemeralPublicKey),
                 crypto:hash(sha256, CertificateDer)]).

sign(Data, PrivateKeyPath) when is_binary(Data) ->
    with_temp_file(Data,
      fun(DataPath) ->
          case openssl_executable() of
              {ok, OpenSSL} ->
                  run_executable(OpenSSL,
                                 ["dgst", "-sha256", "-sign",
                                  filename_to_list(PrivateKeyPath), DataPath]);
              {error, _} = Error -> Error
          end
      end);
sign(_Data, _PrivateKeyPath) ->
    {error, invalid_sign_input}.

verify(CertificateDer, TrustedCaPath, ExpectedPeerId, Data, Signature)
  when is_binary(CertificateDer), is_binary(Data), is_binary(Signature) ->
    case verify_certificate(CertificateDer, TrustedCaPath) of
        ok ->
            case verify_peer_id(CertificateDer, ExpectedPeerId) of
                ok -> verify_signature(CertificateDer, Data, Signature);
                {error, _} = Error -> Error
            end;
        {error, _} = Error -> Error
    end;
verify(_CertificateDer, _TrustedCaPath, _ExpectedPeerId, _Data, _Signature) ->
    {error, invalid_verify_input}.


verify_peer_id(CertificateDer, ExpectedPeerId0) ->
    ExpectedPeerId = peer_id(ExpectedPeerId0),
    try
        #'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{subject = Subject}} =
            public_key:pkix_decode_cert(CertificateDer, otp),
        case subject_common_name(Subject) of
            {ok, ExpectedPeerId} -> ok;
            {ok, ReceivedPeerId} -> {error, {certificate_peer_id_mismatch,
                                             ExpectedPeerId, ReceivedPeerId}};
            {error, _} = Error -> Error
        end
    catch
        Class:Reason -> {error, {remote_certificate_parse_failed, {Class, Reason}}}
    end.

subject_common_name({rdnSequence, Rdns}) -> subject_common_name_rdns(Rdns);
subject_common_name(_) -> {error, certificate_common_name_missing}.

subject_common_name_rdns([]) -> {error, certificate_common_name_missing};
subject_common_name_rdns([Rdn | Rest]) ->
    case subject_common_name_attributes(Rdn) of
        {ok, _} = Found -> Found;
        error -> subject_common_name_rdns(Rest)
    end.

subject_common_name_attributes([]) -> error;
subject_common_name_attributes([{'AttributeTypeAndValue', {2,5,4,3}, Value} | _]) ->
    {ok, attribute_value(Value)};
subject_common_name_attributes([_ | Rest]) -> subject_common_name_attributes(Rest).

attribute_value({utf8String, Value}) -> Value;
attribute_value({printableString, Value}) -> iolist_to_binary(Value);
attribute_value(Value) when is_binary(Value) -> Value;
attribute_value(Value) when is_list(Value) -> iolist_to_binary(Value).

verify_certificate(CertificateDer, TrustedCaPath) ->
    try
        Certificate = public_key:pkix_decode_cert(CertificateDer, otp),
        case vpn_trust_store:load(TrustedCaPath) of
            {ok, TrustStore} -> vpn_trust_store:verify(TrustStore, Certificate);
            {error, Reason} -> {error, {remote_ca_load_failed, Reason}}
        end
    catch
        Class:Reason2 -> {error, {remote_certificate_parse_failed, {Class, Reason2}}}
    end.

verify_signature(CertificateDer, Data, Signature) ->
    with_temp_files(
      [{certificate, der_to_pem(CertificateDer)},
       {data, Data},
       {signature, Signature}],
      fun(Paths) ->
          case openssl_executable() of
              {ok, OpenSSL} ->
                  CertPath = maps:get(certificate, Paths),
                  DataPath = maps:get(data, Paths),
                  SignaturePath = maps:get(signature, Paths),
                  PubPath = temp_path("vpn-handshake-pub", ".pem"),
                  try
                      case run_executable(OpenSSL,
                                          ["x509", "-in", CertPath,
                                           "-pubkey", "-noout"]) of
                          {ok, PublicKeyPem} ->
                              ok = file:write_file(PubPath, PublicKeyPem, [exclusive]),
                              case run_executable(OpenSSL,
                                                  ["dgst", "-sha256",
                                                   "-verify", PubPath,
                                                   "-signature", SignaturePath,
                                                   DataPath]) of
                                  {ok, _} -> ok;
                                  {error, Reason} -> {error, {signature_invalid, Reason}}
                              end;
                          {error, Reason} ->
                              {error, {public_key_extract_failed, Reason}}
                      end
                  after
                      _ = file:delete(PubPath)
                  end;
              {error, _} = Error -> Error
          end
      end).

der_to_pem(Der) ->
    public_key:pem_encode([{'Certificate', Der, not_encrypted}]).

with_temp_file(Binary, Fun) ->
    Path = temp_path("vpn-handshake-data", ".bin"),
    try
        case file:write_file(Path, Binary, [exclusive]) of
            ok -> Fun(Path);
            {error, Reason} -> {error, {temporary_file_failed, Reason}}
        end
    after
        _ = file:delete(Path)
    end.

with_temp_files(Entries, Fun) ->
    Paths = maps:from_list([{Name, temp_path("vpn-handshake-" ++ atom_to_list(Name), ".tmp")}
                            || {Name, _} <- Entries]),
    try
        case write_entries(Entries, Paths) of
            ok -> Fun(Paths);
            {error, _} = Error -> Error
        end
    after
        maps:foreach(fun(_Name, Path) -> _ = file:delete(Path) end, Paths)
    end.

write_entries([], _Paths) -> ok;
write_entries([{Name, Binary} | Rest], Paths) ->
    case file:write_file(maps:get(Name, Paths), Binary, [exclusive]) of
        ok -> write_entries(Rest, Paths);
        {error, Reason} -> {error, {temporary_file_failed, Name, Reason}}
    end.

openssl_executable() ->
    Candidate = case os:getenv("OPENSSL3") of false -> "openssl"; Value -> Value end,
    case filename:pathtype(Candidate) of
        absolute ->
            case filelib:is_regular(Candidate) of
                true -> {ok, Candidate};
                false -> {error, openssl_not_found}
            end;
        _ ->
            case os:find_executable(Candidate) of
                false -> {error, openssl_not_found};
                Path -> {ok, Path}
            end
    end.

run_executable(Executable, Args) ->
    Port = open_port({spawn_executable, Executable},
                     [binary, exit_status, use_stdio, stderr_to_stdout, {args, Args}]),
    collect_port(Port, []).

collect_port(Port, Acc) ->
    receive
        {Port, {data, Data}} -> collect_port(Port, [Acc, Data]);
        {Port, {exit_status, 0}} -> {ok, iolist_to_binary(Acc)};
        {Port, {exit_status, Status}} ->
            {error, {openssl_exit_status, Status, iolist_to_binary(Acc)}}
    after 10000 ->
        catch port_close(Port),
        {error, openssl_timeout}
    end.

temp_path(Prefix, Suffix) ->
    Name = io_lib:format("~s-~p-~p~s",
                         [Prefix, erlang:system_time(microsecond),
                          erlang:unique_integer([positive]), Suffix]),
    filename:join(os:getenv("TMPDIR", "/tmp"), lists:flatten(Name)).

length_prefixed(Binary) -> <<(byte_size(Binary)):16/unsigned, Binary/binary>>.
peer_id(Value) when is_atom(Value) -> atom_to_binary(Value, utf8);
peer_id(Value) when is_binary(Value) -> Value.
filename_to_list(Value) when is_binary(Value) -> binary_to_list(Value);
filename_to_list(Value) when is_list(Value) -> Value.
