%%%-------------------------------------------------------------------
%% @doc VPN packet framing.
%%%-------------------------------------------------------------------
-module(vpn_frame).

-export([encode/3, decode/1]).

-define(VERSION, 1).
-define(TYPE_DATA, 1).
-define(HEADER_SIZE, 12).

encode(PeerId, Seq, Payload) when is_integer(Seq),
                                  Seq >= 0,
                                  is_binary(Payload) ->
    PeerIdBin = peer_id_to_binary(PeerId),
    PeerLen = byte_size(PeerIdBin),
    case PeerLen =< 16#FFFF of
        true ->
            <<?VERSION:8,
              ?TYPE_DATA:8,
              Seq:64/unsigned,
              PeerLen:16/unsigned,
              PeerIdBin:PeerLen/binary,
              Payload/binary>>;
        false ->
            erlang:error({peer_id_too_large, PeerLen})
    end.

decode(Binary) when is_binary(Binary), byte_size(Binary) < ?HEADER_SIZE ->
    {error, truncated_frame};
decode(<<Version:8, _/binary>>) when Version =/= ?VERSION ->
    {error, {unsupported_version, Version}};
decode(<<?VERSION:8, ?TYPE_DATA:8, Seq:64/unsigned, PeerLen:16/unsigned, Rest/binary>>) ->
    case Rest of
        <<PeerIdBin:PeerLen/binary, Payload/binary>> ->
            {ok, #{version => ?VERSION,
                   type => data,
                   seq => Seq,
                   peer_id => PeerIdBin,
                   payload => Payload}};
        _ ->
            {error, truncated_peer_id}
    end;
decode(<<_Version:8, Type:8, _/binary>>) ->
    {error, {unsupported_type, Type}}.

peer_id_to_binary(PeerId) when is_atom(PeerId) ->
    atom_to_binary(PeerId, utf8);
peer_id_to_binary(PeerId) when is_binary(PeerId) ->
    PeerId;
peer_id_to_binary(PeerId) ->
    erlang:error({invalid_peer_id, PeerId}).
