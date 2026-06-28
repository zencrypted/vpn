%%%-------------------------------------------------------------------
%% @doc VPN packet framing.
%%%-------------------------------------------------------------------
-module(vpn_frame).

-export([encode/3, encode/4, decode/1]).

-define(VERSION_LEGACY, 1).
-define(VERSION_EPOCH, 2).
-define(TYPE_DATA, 1).
-define(LEGACY_HEADER_SIZE, 12).
-define(EPOCH_HEADER_SIZE, 16).

encode(PeerId, Seq, Payload) ->
    encode(PeerId, 0, Seq, Payload).

encode(PeerId, KeyEpoch, Seq, Payload)
  when is_integer(KeyEpoch), KeyEpoch >= 0, KeyEpoch =< 16#FFFFFFFF,
       is_integer(Seq), Seq >= 0,
       is_binary(Payload) ->
    PeerIdBin = peer_id_to_binary(PeerId),
    PeerLen = byte_size(PeerIdBin),
    case PeerLen =< 16#FFFF of
        true ->
            <<?VERSION_EPOCH:8,
              ?TYPE_DATA:8,
              KeyEpoch:32/unsigned,
              Seq:64/unsigned,
              PeerLen:16/unsigned,
              PeerIdBin:PeerLen/binary,
              Payload/binary>>;
        false ->
            erlang:error({peer_id_too_large, PeerLen})
    end.

decode(Binary) when is_binary(Binary), byte_size(Binary) < ?LEGACY_HEADER_SIZE ->
    {error, truncated_frame};
decode(<<?VERSION_LEGACY:8, ?TYPE_DATA:8, Seq:64/unsigned,
         PeerLen:16/unsigned, Rest/binary>>) ->
    decode_payload(?VERSION_LEGACY, 0, Seq, PeerLen, Rest);
decode(Binary = <<?VERSION_EPOCH:8, _/binary>>) when byte_size(Binary) < ?EPOCH_HEADER_SIZE ->
    {error, truncated_frame};
decode(<<?VERSION_EPOCH:8, ?TYPE_DATA:8, KeyEpoch:32/unsigned,
         Seq:64/unsigned, PeerLen:16/unsigned, Rest/binary>>) ->
    decode_payload(?VERSION_EPOCH, KeyEpoch, Seq, PeerLen, Rest);
decode(<<Version:8, _/binary>>) when Version =/= ?VERSION_LEGACY,
                                      Version =/= ?VERSION_EPOCH ->
    {error, {unsupported_version, Version}};
decode(<<Version:8, Type:8, _/binary>>)
  when Version =:= ?VERSION_LEGACY; Version =:= ?VERSION_EPOCH ->
    {error, {unsupported_type, Type}}.

decode_payload(Version, KeyEpoch, Seq, PeerLen, Rest) ->
    case Rest of
        <<PeerIdBin:PeerLen/binary, Payload/binary>> ->
            {ok, #{version => Version,
                   type => data,
                   key_epoch => KeyEpoch,
                   seq => Seq,
                   peer_id => PeerIdBin,
                   payload => Payload}};
        _ ->
            {error, truncated_peer_id}
    end.

peer_id_to_binary(PeerId) when is_atom(PeerId) ->
    atom_to_binary(PeerId, utf8);
peer_id_to_binary(PeerId) when is_binary(PeerId) ->
    PeerId;
peer_id_to_binary(PeerId) ->
    erlang:error({invalid_peer_id, PeerId}).
