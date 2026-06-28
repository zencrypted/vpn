%%%-------------------------------------------------------------------
%% @doc Portable checksum encoding for durable VPN projections.
%%
%% The encoding is deliberately independent of the Erlang External Term
%% Format so projection integrity does not depend on a particular OTP major
%% release. Maps are ordered by their canonical key encoding and every value
%% carries an explicit type and length boundary.
%%%-------------------------------------------------------------------
-module(vpn_projection_checksum).

-export([schema_version/0,
         checksum/4,
         legacy_checksum/4,
         canonical_binary/1]).

-define(SCHEMA_VERSION, 2).

schema_version() ->
    ?SCHEMA_VERSION.

checksum(SchemaVersion, ProjectionVersion, Projection, UpdatedAt) ->
    crypto:hash(
      sha256,
      canonical_binary({SchemaVersion,
                        ProjectionVersion,
                        Projection,
                        UpdatedAt})).

legacy_checksum(SchemaVersion, ProjectionVersion, Projection, UpdatedAt) ->
    crypto:hash(
      sha256,
      term_to_binary({SchemaVersion,
                      ProjectionVersion,
                      Projection,
                      UpdatedAt})).

canonical_binary(Term) ->
    iolist_to_binary(encode(Term)).

encode(Term) when is_atom(Term) ->
    value($a, atom_to_binary(Term, utf8));
encode(Term) when is_binary(Term) ->
    value($b, Term);
encode(Term) when is_bitstring(Term) ->
    BitSize = bit_size(Term),
    Padding = (8 - (BitSize rem 8)) rem 8,
    Padded = <<Term/bitstring, 0:Padding>>,
    value($B, [unsigned(BitSize), Padded]);
encode(Term) when is_integer(Term) ->
    value($i, integer_to_binary(Term));
encode(Term) when is_float(Term) ->
    value($f, <<Term:64/float>>);
encode([]) ->
    <<$l, 0:64/unsigned-big>>;
encode(Term) when is_list(Term) ->
    encode_list(Term);
encode(Term) when is_tuple(Term) ->
    Items = [encode(Item) || Item <- tuple_to_list(Term)],
    sequence($t, tuple_size(Term), Items);
encode(Term) when is_map(Term) ->
    Entries0 =
        [{iolist_to_binary(encode(Key)), encode(Value)}
         || {Key, Value} <- maps:to_list(Term)],
    Entries = lists:keysort(1, Entries0),
    Encoded = [[value($k, KeyBin), value($v, ValueEncoding)]
               || {KeyBin, ValueEncoding} <- Entries],
    sequence($m, map_size(Term), Encoded);
encode(Term) ->
    erlang:error({unsupported_canonical_term, term_kind(Term)}).

encode_list(Term) ->
    case proper_list(Term, []) of
        {proper, Items} ->
            Encoded = [encode(Item) || Item <- Items],
            sequence($l, length(Items), Encoded);
        {improper, Heads, Tail} ->
            EncodedHeads = [encode(Item) || Item <- Heads],
            sequence($L,
                     length(Heads),
                     [EncodedHeads, value($d, encode(Tail))])
    end.

proper_list([], Acc) ->
    {proper, lists:reverse(Acc)};
proper_list([Head | Tail], Acc) ->
    proper_list(Tail, [Head | Acc]);
proper_list(Tail, Acc) ->
    {improper, lists:reverse(Acc), Tail}.

sequence(Tag, Count, Items) ->
    [<<Tag>>, unsigned(Count), [framed(Item) || Item <- Items]].

value(Tag, Payload) ->
    [<<Tag>>, framed(Payload)].

framed(Payload) ->
    Size = iolist_size(Payload),
    [unsigned(Size), Payload].

unsigned(Value) when is_integer(Value), Value >= 0 ->
    <<Value:64/unsigned-big>>.

term_kind(Term) when is_pid(Term) -> pid;
term_kind(Term) when is_port(Term) -> port;
term_kind(Term) when is_reference(Term) -> reference;
term_kind(Term) when is_function(Term) -> function;
term_kind(_Term) -> unsupported.
