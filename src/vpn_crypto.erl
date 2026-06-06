%%%-------------------------------------------------------------------
%% @doc PSK authenticated encryption for VPN frames.
%%%-------------------------------------------------------------------
-module(vpn_crypto).

-export([new/0, new/1, new/2, encode/2, decode/2]).

-define(KEY_SIZE, 32).
-define(NONCE_SIZE, 12).
-define(TAG_SIZE, 16).

new() ->
    new(<<0:?KEY_SIZE/unit:8>>).

new(Psk) when is_binary(Psk), byte_size(Psk) =:= ?KEY_SIZE ->
    new(Psk, undefined);
new(Psk) ->
    erlang:error({invalid_psk, Psk}).

new(Psk, PeerId) when is_binary(Psk), byte_size(Psk) =:= ?KEY_SIZE ->
    #{psk => Psk, peer_id => peer_id_to_binary(PeerId)};
new(Psk, _PeerId) ->
    erlang:error({invalid_psk, Psk}).

encode(Frame, State = #{psk := Psk, peer_id := PeerId}) ->
    Seq = frame_seq(Frame),
    Nonce = nonce(PeerId, Seq),
    {Ciphertext, Tag} =
        crypto:crypto_one_time_aead(chacha20_poly1305,
                                    Psk,
                                    Nonce,
                                    Frame,
                                    <<>>,
                                    true),
    {ok, <<Nonce/binary, Ciphertext/binary, Tag/binary>>, State}.

decode(Packet, State = #{psk := Psk}) when byte_size(Packet) >= ?NONCE_SIZE + ?TAG_SIZE ->
    CipherSize = byte_size(Packet) - ?NONCE_SIZE - ?TAG_SIZE,
    <<Nonce:?NONCE_SIZE/binary, Ciphertext:CipherSize/binary, Tag:?TAG_SIZE/binary>> = Packet,
    case crypto:crypto_one_time_aead(chacha20_poly1305,
                                     Psk,
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

frame_seq(<<1:8, 1:8, Seq:64/unsigned, _/binary>>) ->
    Seq;
frame_seq(_Frame) ->
    erlang:error(invalid_frame).

nonce(PeerId, Seq) when is_integer(Seq), Seq >= 0 ->
    <<Prefix:32, _/binary>> = crypto:hash(sha256, PeerId),
    <<Prefix:32, Seq:64/unsigned>>.

peer_id_to_binary(PeerId) when is_atom(PeerId) ->
    atom_to_binary(PeerId, utf8);
peer_id_to_binary(PeerId) when is_binary(PeerId) ->
    PeerId;
peer_id_to_binary(PeerId) ->
    erlang:error({invalid_peer_id, PeerId}).
