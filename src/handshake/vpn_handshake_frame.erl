%%%-------------------------------------------------------------------
%% @doc Wire format for VPN control-plane handshake frames.
%%
%% Version 4 adds an authenticated exchange-kind marker to hello frames.
%%%-------------------------------------------------------------------
-module(vpn_handshake_frame).

-export([encode_hello/3, encode_hello/4, encode_hello/5, encode_proof/6, encode_proof/7, encode_ack/4,
         decode/1, is_control/1]).

-define(MAGIC, "VPNH").
-define(VERSION, 4).
-define(LEGACY_VERSION, 3).
-define(TYPE_HELLO, 1).
-define(TYPE_ACK, 2).
-define(TYPE_PROOF, 3).
-define(ID_SIZE, 16).
-define(FIXED_SIZE, 56).

encode_hello(PeerId, SessionId, Nonce) ->
    encode_hello(PeerId, SessionId, Nonce, <<>>, initial).

encode_hello(PeerId, SessionId, Nonce, EphemeralPublicKey) ->
    encode_hello(PeerId, SessionId, Nonce, EphemeralPublicKey, initial).

encode_hello(PeerId0, SessionId, Nonce, EphemeralPublicKey, ExchangeKind)
  when is_binary(EphemeralPublicKey) ->
    PeerId = peer_id_to_binary(PeerId0),
    PeerLen = byte_size(PeerId),
    KeyLen = byte_size(EphemeralPublicKey),
    validate_lengths(PeerLen, 0, 0),
    validate_key_length(KeyLen),
    KindCode = exchange_kind_code(ExchangeKind),
    <<?MAGIC, ?VERSION:8, ?TYPE_HELLO:8,
      SessionId:?ID_SIZE/binary, 0:?ID_SIZE/unit:8,
      PeerLen:16/unsigned, Nonce:?ID_SIZE/binary,
      KeyLen:16/unsigned, KindCode:8,
      PeerId/binary, EphemeralPublicKey/binary>>.

encode_ack(PeerId, SessionId, AckFor, Nonce) ->
    encode_basic(?TYPE_ACK, PeerId, SessionId, AckFor, Nonce).

encode_proof(PeerId, SessionId, AckFor, Nonce, CertificateDer, Signature) ->
    encode_proof(PeerId, SessionId, AckFor, Nonce, <<>>, CertificateDer, Signature).

encode_proof(PeerId0, SessionId, AckFor, Nonce, EphemeralPublicKey, CertificateDer, Signature)
  when is_binary(EphemeralPublicKey), is_binary(CertificateDer), is_binary(Signature) ->
    PeerId = peer_id_to_binary(PeerId0),
    PeerLen = byte_size(PeerId),
    KeyLen = byte_size(EphemeralPublicKey),
    CertLen = byte_size(CertificateDer),
    SignatureLen = byte_size(Signature),
    validate_lengths(PeerLen, CertLen, SignatureLen),
    validate_key_length(KeyLen),
    <<?MAGIC, ?VERSION:8, ?TYPE_PROOF:8,
      SessionId:?ID_SIZE/binary, AckFor:?ID_SIZE/binary,
      PeerLen:16/unsigned, Nonce:?ID_SIZE/binary,
      KeyLen:16/unsigned, CertLen:32/unsigned, SignatureLen:16/unsigned,
      PeerId/binary, EphemeralPublicKey/binary, CertificateDer/binary, Signature/binary>>.

is_control(<<?MAGIC, _/binary>>) -> true;
is_control(_) -> false.

decode(Binary) when not is_binary(Binary) ->
    {error, invalid_control_frame};
decode(Binary) when byte_size(Binary) < ?FIXED_SIZE ->
    {error, truncated_control_frame};
decode(<<?MAGIC, Version:8, _/binary>>)
  when Version =/= ?VERSION, Version =/= ?LEGACY_VERSION ->
    {error, {unsupported_handshake_version, Version}};
decode(<<?MAGIC, Version:8, Type:8,
         SessionId:?ID_SIZE/binary, AckFor:?ID_SIZE/binary,
         PeerLen:16/unsigned, Nonce:?ID_SIZE/binary, Rest/binary>>) ->
    decode_payload(Version, Type, SessionId, AckFor, PeerLen, Nonce, Rest);
decode(_) ->
    {error, invalid_control_magic}.

encode_basic(Type, PeerId0, SessionId, AckFor, Nonce)
  when byte_size(SessionId) =:= ?ID_SIZE,
       byte_size(AckFor) =:= ?ID_SIZE,
       byte_size(Nonce) =:= ?ID_SIZE ->
    PeerId = peer_id_to_binary(PeerId0),
    PeerLen = byte_size(PeerId),
    validate_lengths(PeerLen, 0, 0),
    <<?MAGIC, ?VERSION:8, Type:8,
      SessionId/binary, AckFor/binary,
      PeerLen:16/unsigned, Nonce/binary, PeerId/binary>>.

decode_payload(?VERSION, ?TYPE_HELLO, SessionId, _AckFor, PeerLen, Nonce,
               <<KeyLen:16/unsigned, KindCode:8, Payload/binary>>) ->
    case exchange_kind(KindCode) of
        {ok, ExchangeKind} ->
            decode_hello_payload(?VERSION, SessionId, PeerLen, Nonce, KeyLen,
                                 ExchangeKind, Payload);
        {error, _} = Error -> Error
    end;
decode_payload(?LEGACY_VERSION, ?TYPE_HELLO, SessionId, _AckFor, PeerLen, Nonce,
               <<KeyLen:16/unsigned, Payload/binary>>) ->
    decode_hello_payload(?LEGACY_VERSION, SessionId, PeerLen, Nonce, KeyLen,
                         initial, Payload);
decode_payload(_Version, ?TYPE_HELLO, _SessionId, _AckFor, _PeerLen, _Nonce, _Rest) ->
    {error, truncated_control_frame};
decode_payload(Version, ?TYPE_PROOF, SessionId, AckFor, PeerLen, Nonce,
               <<KeyLen:16/unsigned, CertLen:32/unsigned, SignatureLen:16/unsigned,
                 Payload/binary>>) ->
    Expected = PeerLen + KeyLen + CertLen + SignatureLen,
    case byte_size(Payload) of
        Expected ->
            <<PeerId:PeerLen/binary,
              EphemeralPublicKey:KeyLen/binary,
              CertificateDer:CertLen/binary,
              Signature:SignatureLen/binary>> = Payload,
            {ok, #{version => Version,
                   type => proof,
                   session_id => SessionId,
                   ack_for => AckFor,
                   peer_id => PeerId,
                   nonce => Nonce,
                   ephemeral_public_key => EphemeralPublicKey,
                   certificate_der => CertificateDer,
                   signature => Signature}};
        _ ->
            {error, invalid_control_length}
    end;
decode_payload(_Version, ?TYPE_PROOF, _SessionId, _AckFor, _PeerLen, _Nonce, _Rest) ->
    {error, truncated_control_frame};
decode_payload(Version, Type, SessionId, AckFor, PeerLen, Nonce, Rest) ->
    case Rest of
        <<PeerId:PeerLen/binary>> ->
            decode_basic_type(Version, Type, SessionId, AckFor, PeerId, Nonce);
        _ ->
            {error, invalid_control_length}
    end.

decode_hello_payload(Version, SessionId, PeerLen, Nonce, KeyLen, ExchangeKind, Payload) ->
    Expected = PeerLen + KeyLen,
    case byte_size(Payload) of
        Expected ->
            <<PeerId:PeerLen/binary, EphemeralPublicKey:KeyLen/binary>> = Payload,
            Base = #{version => Version,
                     type => hello,
                     exchange_kind => ExchangeKind,
                     session_id => SessionId,
                     peer_id => PeerId,
                     nonce => Nonce},
            case KeyLen of
                0 -> {ok, Base};
                _ -> {ok, Base#{ephemeral_public_key => EphemeralPublicKey}}
            end;
        _ -> {error, invalid_control_length}
    end.

decode_basic_type(Version, ?TYPE_ACK, SessionId, AckFor, PeerId, Nonce) ->
    {ok, #{version => Version,
           type => ack,
           session_id => SessionId,
           ack_for => AckFor,
           peer_id => PeerId,
           nonce => Nonce}};
decode_basic_type(_Version, Type, _SessionId, _AckFor, _PeerId, _Nonce) ->
    {error, {unsupported_handshake_type, Type}}.

exchange_kind_code(initial) -> 0;
exchange_kind_code(rekey) -> 1;
exchange_kind_code(Kind) -> erlang:error({invalid_exchange_kind, Kind}).

exchange_kind(0) -> {ok, initial};
exchange_kind(1) -> {ok, rekey};
exchange_kind(Code) -> {error, {unsupported_exchange_kind, Code}}.

validate_lengths(PeerLen, CertLen, SignatureLen)
  when PeerLen =< 16#FFFF, CertLen =< 16#FFFFFFFF, SignatureLen =< 16#FFFF -> ok;
validate_lengths(PeerLen, _CertLen, _SignatureLen) when PeerLen > 16#FFFF ->
    erlang:error({peer_id_too_large, PeerLen});
validate_lengths(_PeerLen, CertLen, _SignatureLen) when CertLen > 16#FFFFFFFF ->
    erlang:error({certificate_too_large, CertLen});
validate_lengths(_PeerLen, _CertLen, SignatureLen) ->
    erlang:error({signature_too_large, SignatureLen}).

validate_key_length(KeyLen) when KeyLen =< 16#FFFF -> ok;
validate_key_length(KeyLen) -> erlang:error({ephemeral_key_too_large, KeyLen}).

peer_id_to_binary(PeerId) when is_atom(PeerId) -> atom_to_binary(PeerId, utf8);
peer_id_to_binary(PeerId) when is_binary(PeerId) -> PeerId;
peer_id_to_binary(PeerId) -> erlang:error({invalid_peer_id, PeerId}).
