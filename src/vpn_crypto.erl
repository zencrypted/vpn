%%%-------------------------------------------------------------------
%% @doc PSK authenticated encryption for VPN frames.
%%%-------------------------------------------------------------------
-module(vpn_crypto).

-export([new/0, new/1, encode/2, decode/2]).

-define(KEY_SIZE, 32).
-define(NONCE_SIZE, 12).
-define(TAG_SIZE, 16).

new() ->
    new(<<0:?KEY_SIZE/unit:8>>).

new(Psk) when is_binary(Psk), byte_size(Psk) =:= ?KEY_SIZE ->
    #{psk => Psk};
new(Psk) ->
    erlang:error({invalid_psk, Psk}).

encode(Frame, State = #{psk := Psk}) ->
    Seq = frame_seq(Frame),
    Nonce = nonce(Seq),
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

nonce(Seq) when is_integer(Seq), Seq >= 0 ->
    <<0:32, Seq:64/unsigned>>.
