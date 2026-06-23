%%%-------------------------------------------------------------------
%% @doc Ephemeral ECDH and HKDF-SHA256 session-key derivation.
%%%-------------------------------------------------------------------
-module(vpn_session_kdf).

-export([generate_key_pair/0, derive/9]).

-define(KEY_SIZE, 32).

-spec generate_key_pair() -> {binary(), binary()}.
generate_key_pair() ->
    crypto:generate_key(ecdh, secp384r1).

-spec derive(binary(), binary(), binary(), binary(), binary(), binary(),
             binary(), binary(), binary()) -> {ok, map()} | {error, term()}.
derive(LocalPeerId, RemotePeerId,
       LocalSessionId, RemoteSessionId,
       LocalNonce, RemoteNonce,
       LocalPrivateKey, LocalPublicKey, RemotePublicKey) ->
    try
        SharedSecret = crypto:compute_key(ecdh, RemotePublicKey,
                                          LocalPrivateKey, secp384r1),
        {FirstPeer, SecondPeer,
         FirstSession, SecondSession,
         FirstNonce, SecondNonce,
         FirstPublic, SecondPublic,
         LocalIsFirst} =
            canonical(LocalPeerId, RemotePeerId,
                      LocalSessionId, RemoteSessionId,
                      LocalNonce, RemoteNonce,
                      LocalPublicKey, RemotePublicKey),
        Salt = crypto:hash(sha256,
                           [<<"vpn-session-salt-v1">>,
                            length_prefixed(FirstPeer), length_prefixed(SecondPeer),
                            FirstSession, SecondSession,
                            FirstNonce, SecondNonce]),
        Info = iolist_to_binary([<<"vpn-session-keys-v1">>,
                                 length_prefixed(FirstPublic),
                                 length_prefixed(SecondPublic)]),
        Prk = crypto:mac(hmac, sha256, Salt, SharedSecret),
        <<FirstToSecond:?KEY_SIZE/binary,
          SecondToFirst:?KEY_SIZE/binary>> = hkdf_expand(Prk, Info, 2 * ?KEY_SIZE),
        {TxKey, RxKey} = case LocalIsFirst of
                             true -> {FirstToSecond, SecondToFirst};
                             false -> {SecondToFirst, FirstToSecond}
                         end,
        {ok, #{tx_key => TxKey,
               rx_key => RxKey,
               key_source => ephemeral_ecdh_hkdf_sha256,
               shared_secret_fingerprint => hex(crypto:hash(sha256, SharedSecret))}}
    catch
        Class:Reason -> {error, {session_key_derivation_failed, {Class, Reason}}}
    end.

canonical(LocalPeerId, RemotePeerId,
          LocalSessionId, RemoteSessionId,
          LocalNonce, RemoteNonce,
          LocalPublicKey, RemotePublicKey) ->
    case LocalPeerId =< RemotePeerId of
        true -> {LocalPeerId, RemotePeerId,
                 LocalSessionId, RemoteSessionId,
                 LocalNonce, RemoteNonce,
                 LocalPublicKey, RemotePublicKey, true};
        false -> {RemotePeerId, LocalPeerId,
                  RemoteSessionId, LocalSessionId,
                  RemoteNonce, LocalNonce,
                  RemotePublicKey, LocalPublicKey, false}
    end.

hkdf_expand(Prk, Info, Length) ->
    hkdf_expand(Prk, Info, Length, <<>>, <<>>, 1).

hkdf_expand(_Prk, _Info, Length, Acc, _Previous, _Counter)
  when byte_size(Acc) >= Length ->
    binary:part(Acc, 0, Length);
hkdf_expand(Prk, Info, Length, Acc, Previous, Counter) when Counter =< 255 ->
    Block = crypto:mac(hmac, sha256, Prk,
                       <<Previous/binary, Info/binary, Counter:8>>),
    hkdf_expand(Prk, Info, Length, <<Acc/binary, Block/binary>>, Block, Counter + 1).

length_prefixed(Binary) -> <<(byte_size(Binary)):16/unsigned, Binary/binary>>.
hex(Binary) -> iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).
