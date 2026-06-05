%%%-------------------------------------------------------------------
%% @doc VPN packet framing.
%%%-------------------------------------------------------------------
-module(vpn_frame).

-export([encode/3, decode/1]).

-define(VERSION, 1).
-define(TYPE_DATA, 1).
-define(HEADER_SIZE, 10).

encode(_PeerId, Seq, Payload) when is_integer(Seq),
                                  Seq >= 0,
                                  is_binary(Payload) ->
    <<?VERSION:8, ?TYPE_DATA:8, Seq:64/unsigned, Payload/binary>>.

decode(Binary) when is_binary(Binary), byte_size(Binary) < ?HEADER_SIZE ->
    {error, truncated_frame};
decode(<<?VERSION:8, ?TYPE_DATA:8, Seq:64/unsigned, Payload/binary>>) ->
    {ok, #{version => ?VERSION,
           type => data,
           seq => Seq,
           payload => Payload}};
decode(<<Version:8, _/binary>>) when Version =/= ?VERSION ->
    {error, {unsupported_version, Version}};
decode(<<_Version:8, Type:8, _/binary>>) ->
    {error, {unsupported_type, Type}}.
