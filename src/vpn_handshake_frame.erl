%%%-------------------------------------------------------------------
%% @doc Wire format for VPN control-plane handshake frames.
%%
%% Version 2 adds a certificate proof frame while retaining explicit
%% separation from encrypted dataplane packets.
%%%-------------------------------------------------------------------
-module(vpn_handshake_frame).

-export([encode_hello/3, encode_proof/6, encode_ack/4, decode/1, is_control/1]).

-define(MAGIC, "VPNH").
-define(VERSION, 2).
-define(TYPE_HELLO, 1).
-define(TYPE_ACK, 2).
-define(TYPE_PROOF, 3).
-define(ID_SIZE, 16).
-define(FIXED_SIZE, 56).

encode_hello(PeerId, SessionId, Nonce) ->
    encode_basic(?TYPE_HELLO, PeerId, SessionId, <<0:?ID_SIZE/unit:8>>, Nonce).

encode_ack(PeerId, SessionId, AckFor, Nonce) ->
    encode_basic(?TYPE_ACK, PeerId, SessionId, AckFor, Nonce).

encode_proof(PeerId0, SessionId, AckFor, Nonce, CertificateDer, Signature)
  when is_binary(CertificateDer), is_binary(Signature) ->
    PeerId = peer_id_to_binary(PeerId0),
    PeerLen = byte_size(PeerId),
    CertLen = byte_size(CertificateDer),
    SignatureLen = byte_size(Signature),
    validate_lengths(PeerLen, CertLen, SignatureLen),
    <<?MAGIC, ?VERSION:8, ?TYPE_PROOF:8,
      SessionId:?ID_SIZE/binary, AckFor:?ID_SIZE/binary,
      PeerLen:16/unsigned, Nonce:?ID_SIZE/binary,
      CertLen:32/unsigned, SignatureLen:16/unsigned,
      PeerId/binary, CertificateDer/binary, Signature/binary>>.

is_control(<<?MAGIC, _/binary>>) -> true;
is_control(_) -> false.

decode(Binary) when not is_binary(Binary) ->
    {error, invalid_control_frame};
decode(Binary) when byte_size(Binary) < ?FIXED_SIZE ->
    {error, truncated_control_frame};
decode(<<?MAGIC, Version:8, _/binary>>) when Version =/= ?VERSION ->
    {error, {unsupported_handshake_version, Version}};
decode(<<?MAGIC, ?VERSION:8, Type:8,
         SessionId:?ID_SIZE/binary, AckFor:?ID_SIZE/binary,
         PeerLen:16/unsigned, Nonce:?ID_SIZE/binary, Rest/binary>>) ->
    decode_payload(Type, SessionId, AckFor, PeerLen, Nonce, Rest);
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

decode_payload(?TYPE_PROOF, SessionId, AckFor, PeerLen, Nonce,
               <<CertLen:32/unsigned, SignatureLen:16/unsigned, Payload/binary>>) ->
    Expected = PeerLen + CertLen + SignatureLen,
    case byte_size(Payload) of
        Expected ->
            <<PeerId:PeerLen/binary,
              CertificateDer:CertLen/binary,
              Signature:SignatureLen/binary>> = Payload,
            {ok, #{version => ?VERSION,
                   type => proof,
                   session_id => SessionId,
                   ack_for => AckFor,
                   peer_id => PeerId,
                   nonce => Nonce,
                   certificate_der => CertificateDer,
                   signature => Signature}};
        _ ->
            {error, invalid_control_length}
    end;
decode_payload(?TYPE_PROOF, _SessionId, _AckFor, _PeerLen, _Nonce, _Rest) ->
    {error, truncated_control_frame};
decode_payload(Type, SessionId, AckFor, PeerLen, Nonce, Rest) ->
    case Rest of
        <<PeerId:PeerLen/binary>> ->
            decode_basic_type(Type, SessionId, AckFor, PeerId, Nonce);
        _ ->
            {error, invalid_control_length}
    end.

decode_basic_type(?TYPE_HELLO, SessionId, _AckFor, PeerId, Nonce) ->
    {ok, #{version => ?VERSION,
           type => hello,
           session_id => SessionId,
           peer_id => PeerId,
           nonce => Nonce}};
decode_basic_type(?TYPE_ACK, SessionId, AckFor, PeerId, Nonce) ->
    {ok, #{version => ?VERSION,
           type => ack,
           session_id => SessionId,
           ack_for => AckFor,
           peer_id => PeerId,
           nonce => Nonce}};
decode_basic_type(Type, _SessionId, _AckFor, _PeerId, _Nonce) ->
    {error, {unsupported_handshake_type, Type}}.

validate_lengths(PeerLen, CertLen, SignatureLen)
  when PeerLen =< 16#FFFF, CertLen =< 16#FFFFFFFF, SignatureLen =< 16#FFFF -> ok;
validate_lengths(PeerLen, _CertLen, _SignatureLen) when PeerLen > 16#FFFF ->
    erlang:error({peer_id_too_large, PeerLen});
validate_lengths(_PeerLen, CertLen, _SignatureLen) when CertLen > 16#FFFFFFFF ->
    erlang:error({certificate_too_large, CertLen});
validate_lengths(_PeerLen, _CertLen, SignatureLen) ->
    erlang:error({signature_too_large, SignatureLen}).

peer_id_to_binary(PeerId) when is_atom(PeerId) -> atom_to_binary(PeerId, utf8);
peer_id_to_binary(PeerId) when is_binary(PeerId) -> PeerId;
peer_id_to_binary(PeerId) -> erlang:error({invalid_peer_id, PeerId}).
