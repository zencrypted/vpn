%%%-------------------------------------------------------------------
%% @doc Wire format for the VPN control-plane handshake skeleton.
%%
%% Control frames are intentionally distinct from encrypted data packets.
%% They do not authenticate either peer yet; certificate proof is added by
%% the next protocol stage.
%%%-------------------------------------------------------------------
-module(vpn_handshake_frame).

-export([encode_hello/3, encode_ack/4, decode/1, is_control/1]).

-define(MAGIC, "VPNH").
-define(VERSION, 1).
-define(TYPE_HELLO, 1).
-define(TYPE_ACK, 2).
-define(ID_SIZE, 16).
-define(FIXED_SIZE, 56).

encode_hello(PeerId, SessionId, Nonce) ->
    encode(?TYPE_HELLO, PeerId, SessionId, <<0:?ID_SIZE/unit:8>>, Nonce).

encode_ack(PeerId, SessionId, AckFor, Nonce) ->
    encode(?TYPE_ACK, PeerId, SessionId, AckFor, Nonce).

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
    case Rest of
        <<PeerId:PeerLen/binary>> ->
            decode_type(Type, SessionId, AckFor, PeerId, Nonce);
        _ ->
            {error, invalid_control_length}
    end;
decode(_) ->
    {error, invalid_control_magic}.

encode(Type, PeerId0, SessionId, AckFor, Nonce)
  when byte_size(SessionId) =:= ?ID_SIZE,
       byte_size(AckFor) =:= ?ID_SIZE,
       byte_size(Nonce) =:= ?ID_SIZE ->
    PeerId = peer_id_to_binary(PeerId0),
    PeerLen = byte_size(PeerId),
    case PeerLen =< 16#FFFF of
        true ->
            <<?MAGIC, ?VERSION:8, Type:8,
              SessionId/binary, AckFor/binary,
              PeerLen:16/unsigned, Nonce/binary, PeerId/binary>>;
        false ->
            erlang:error({peer_id_too_large, PeerLen})
    end.

decode_type(?TYPE_HELLO, SessionId, _AckFor, PeerId, Nonce) ->
    {ok, #{version => ?VERSION,
           type => hello,
           session_id => SessionId,
           peer_id => PeerId,
           nonce => Nonce}};
decode_type(?TYPE_ACK, SessionId, AckFor, PeerId, Nonce) ->
    {ok, #{version => ?VERSION,
           type => ack,
           session_id => SessionId,
           ack_for => AckFor,
           peer_id => PeerId,
           nonce => Nonce}};
decode_type(Type, _SessionId, _AckFor, _PeerId, _Nonce) ->
    {error, {unsupported_handshake_type, Type}}.

peer_id_to_binary(PeerId) when is_atom(PeerId) -> atom_to_binary(PeerId, utf8);
peer_id_to_binary(PeerId) when is_binary(PeerId) -> PeerId;
peer_id_to_binary(PeerId) -> erlang:error({invalid_peer_id, PeerId}).
