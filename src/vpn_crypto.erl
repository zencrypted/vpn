%%%-------------------------------------------------------------------
%% @doc Authenticated encryption for VPN dataplane frames.
%%
%% Legacy peers may still use a symmetric PSK. Certificate-control peers
%% install directional session keys derived by the handshake.
%%%-------------------------------------------------------------------
-module(vpn_crypto).

-export([new/2, new_session/3, new_session/4, encode/2, decode/2, info/1]).

-define(KEY_SIZE, 32).
-define(NONCE_SIZE, 12).
-define(TAG_SIZE, 16).

new(Psk, PeerId) when is_binary(Psk), byte_size(Psk) =:= ?KEY_SIZE ->
    #{tx_key => Psk,
      rx_key => Psk,
      peer_id => peer_id_to_binary(PeerId),
      key_source => psk};
new(Psk, _PeerId) ->
    erlang:error({invalid_psk, Psk}).

new_session(TxKey, RxKey, PeerId) ->
    new_session(TxKey, RxKey, PeerId, 1).

new_session(TxKey, RxKey, PeerId, KeyEpoch)
  when is_binary(TxKey), byte_size(TxKey) =:= ?KEY_SIZE,
       is_binary(RxKey), byte_size(RxKey) =:= ?KEY_SIZE,
       is_integer(KeyEpoch), KeyEpoch > 0 ->
    #{tx_key => TxKey,
      rx_key => RxKey,
      peer_id => peer_id_to_binary(PeerId),
      key_epoch => KeyEpoch,
      key_source => ephemeral_ecdh_hkdf_sha256};
new_session(TxKey, RxKey, _PeerId, KeyEpoch) ->
    erlang:error({invalid_session_keys, TxKey, RxKey, KeyEpoch}).

encode(Frame, State = #{tx_key := TxKey, peer_id := PeerId}) ->
    {KeyEpoch, Seq} = frame_context(Frame),
    Nonce = nonce(PeerId, KeyEpoch, Seq),
    {Ciphertext, Tag} =
        crypto:crypto_one_time_aead(chacha20_poly1305,
                                    TxKey,
                                    Nonce,
                                    Frame,
                                    <<>>,
                                    true),
    {ok, <<Nonce/binary, Ciphertext/binary, Tag/binary>>, State}.

decode(Packet, State = #{rx_key := RxKey}) when byte_size(Packet) >= ?NONCE_SIZE + ?TAG_SIZE ->
    CipherSize = byte_size(Packet) - ?NONCE_SIZE - ?TAG_SIZE,
    <<Nonce:?NONCE_SIZE/binary, Ciphertext:CipherSize/binary, Tag:?TAG_SIZE/binary>> = Packet,
    case crypto:crypto_one_time_aead(chacha20_poly1305,
                                     RxKey,
                                     Nonce,
                                     Ciphertext,
                                     <<>>,
                                     Tag,
                                     false) of
        error ->
            {error, authentication_failed, State};
        Plaintext ->
            {ok, Plaintext, State}
    end;
decode(_Packet, State) ->
    {error, truncated_encrypted_packet, State}.

info(State) ->
    maps:with([key_source, key_epoch], State).

frame_context(<<1:8, 1:8, Seq:64/unsigned, _/binary>>) ->
    {0, Seq};
frame_context(<<2:8, 1:8, KeyEpoch:32/unsigned, Seq:64/unsigned, _/binary>>) ->
    {KeyEpoch, Seq};
frame_context(_Frame) ->
    erlang:error(invalid_frame).

nonce(PeerId, KeyEpoch, Seq)
  when is_integer(KeyEpoch), KeyEpoch >= 0,
       is_integer(Seq), Seq >= 0 ->
    <<Prefix:32, _/binary>> = crypto:hash(sha256, PeerId),
    EpochSeq = <<KeyEpoch:32/unsigned, Seq:64/unsigned>>,
    <<Nonce:12/binary, _/binary>> = crypto:hash(sha256, <<Prefix:32, EpochSeq/binary>>),
    Nonce.

peer_id_to_binary(PeerId) when is_atom(PeerId) ->
    atom_to_binary(PeerId, utf8);
peer_id_to_binary(PeerId) when is_binary(PeerId) ->
    PeerId;
peer_id_to_binary(PeerId) ->
    erlang:error({invalid_peer_id, PeerId}).
