%%%-------------------------------------------------------------------
%% @doc Strict parser for the canonical ovpn/v1 provisioning envelope.
%%
%% This module parses configuration only. It does not resolve the private-key
%% reference, validate X.509 material, mutate runtime state, or start a session.
%%%-------------------------------------------------------------------
-module(vpn_ovpn_parser).

-export([parse/1, parse_file/1]).

-define(MAX_ENVELOPE_BYTES, 1048576).

-type parse_error() :: term().
-type peer_config() :: map().

-spec parse_file(file:filename_all()) ->
    {ok, peer_config()} | {error, parse_error()}.
parse_file(Path) ->
    case file:read_file(Path) of
        {ok, Binary} ->
            parse(Binary);
        {error, Reason} ->
            {error, {file_read_failed, Reason}}
    end.

-spec parse(binary()) -> {ok, peer_config()} | {error, parse_error()}.
parse(Binary) when is_binary(Binary), byte_size(Binary) =< ?MAX_ENVELOPE_BYTES ->
    case validate_text(Binary) of
        ok ->
            Lines = split_lines(Binary),
            Initial = #{seen => #{}, values => #{}, options => #{}},
            case parse_lines(Lines, 1, normal, Initial) of
                {ok, State} ->
                    finalize(State);
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end;
parse(Binary) when is_binary(Binary) ->
    {error, envelope_too_large};
parse(_Other) ->
    {error, invalid_envelope}.

validate_text(<<16#EF, 16#BB, 16#BF, _/binary>>) ->
    {error, byte_order_mark_forbidden};
validate_text(Binary) ->
    case unicode:characters_to_binary(Binary, utf8, utf8) of
        Binary -> ok;
        {error, _Converted, _Rest} -> {error, invalid_utf8};
        {incomplete, _Converted, _Rest} -> {error, invalid_utf8}
    end.

split_lines(Binary) ->
    [strip_trailing_cr(Line) || Line <- binary:split(Binary, <<"\n">>, [global])].

strip_trailing_cr(<<>>) ->
    <<>>;
strip_trailing_cr(Binary) ->
    Size = byte_size(Binary),
    case binary:at(Binary, Size - 1) of
        $\r -> binary:part(Binary, 0, Size - 1);
        _ -> Binary
    end.

parse_lines([], _LineNumber, normal, State) ->
    {ok, State};
parse_lines([], _LineNumber, {block, Name, StartLine, _Lines}, _State) ->
    {error, {line, StartLine, {unterminated_block, Name}}};
parse_lines([Line | Rest], LineNumber, normal, State) ->
    Trimmed = trim(Line),
    case classify_normal_line(Trimmed) of
        ignore ->
            parse_lines(Rest, LineNumber + 1, normal, State);
        {block_start, Name} ->
            case mark_seen(Name, LineNumber, State) of
                {ok, State1} ->
                    parse_lines(Rest, LineNumber + 1,
                                {block, Name, LineNumber, []}, State1);
                {error, _} = Error ->
                    Error
            end;
        {unexpected_block_end, Name} ->
            {error, {line, LineNumber, {unexpected_block_end, Name}}};
        directive ->
            case parse_directive(Trimmed, LineNumber, State) of
                {ok, State1} ->
                    parse_lines(Rest, LineNumber + 1, normal, State1);
                {error, _} = Error ->
                    Error
            end
    end;
parse_lines([Line | Rest], LineNumber,
            {block, Name, StartLine, AccLines}, State) ->
    Trimmed = trim(Line),
    case block_end(Trimmed) of
        Name ->
            Pem = block_binary(lists:reverse(AccLines)),
            case validate_certificate_block(Name, Pem) of
                ok ->
                    State1 = put_value(Name, Pem, State),
                    parse_lines(Rest, LineNumber + 1, normal, State1);
                {error, Reason} ->
                    {error, {line, StartLine, Reason}}
            end;
        none ->
            case block_start_or_end(Trimmed) of
                none ->
                    parse_lines(Rest, LineNumber + 1,
                                {block, Name, StartLine, [Line | AccLines]}, State);
                Other ->
                    {error, {line, LineNumber,
                             {unexpected_block_marker, Other}}}
            end;
        OtherName ->
            {error, {line, LineNumber,
                     {mismatched_block_end, Name, OtherName}}}
    end.

classify_normal_line(<<>>) -> ignore;
classify_normal_line(<<$#, _/binary>>) -> ignore;
classify_normal_line(<<$;, _/binary>>) -> ignore;
classify_normal_line(<<"<ca>">>) -> {block_start, ca};
classify_normal_line(<<"<cert>">>) -> {block_start, cert};
classify_normal_line(<<"</ca>">>) -> {unexpected_block_end, ca};
classify_normal_line(<<"</cert>">>) -> {unexpected_block_end, cert};
classify_normal_line(_Line) -> directive.

block_end(<<"</ca>">>) -> ca;
block_end(<<"</cert>">>) -> cert;
block_end(_Line) -> none.

block_start_or_end(<<"<ca>">>) -> {start, ca};
block_start_or_end(<<"<cert>">>) -> {start, cert};
block_start_or_end(<<"</ca>">>) -> {'end', ca};
block_start_or_end(<<"</cert>">>) -> {'end', cert};
block_start_or_end(_Line) -> none.

parse_directive(Line, LineNumber, State) ->
    Tokens = whitespace_tokens(Line),
    case Tokens of
        [<<"client">>] ->
            put_singleton(client, true, LineNumber, State);
        [<<"dev">>, <<"tun">>] ->
            put_singleton(dev, tun, LineNumber, State);
        [<<"dev">>, _Other] ->
            {error, {line, LineNumber, unsupported_tunnel_device}};
        [<<"proto">>, <<"udp">>] ->
            put_singleton(proto, udp, LineNumber, State);
        [<<"proto">>, _Other] ->
            {error, {line, LineNumber, unsupported_transport}};
        [<<"remote">>, Host, PortBinary] ->
            parse_remote(Host, PortBinary, LineNumber, State);
        [<<"key">>, Reference] ->
            case vpn_ovpn_envelope:validate_key_reference(Reference) of
                ok -> put_singleton(key, Reference, LineNumber, State);
                {error, Reason} -> {error, {line, LineNumber, Reason}}
            end;
        [<<"nobind">>] ->
            put_option(nobind, true, LineNumber, State);
        [<<"persist-key">>] ->
            put_option(persist_key, true, LineNumber, State);
        [<<"persist-tun">>] ->
            put_option(persist_tun, true, LineNumber, State);
        [<<"remote-cert-tls">>, <<"server">>] ->
            put_option(remote_cert_tls, server, LineNumber, State);
        [<<"remote-cert-tls">>, _Other] ->
            {error, {line, LineNumber, unsupported_remote_certificate_role}};
        [<<"verb">>, LevelBinary] ->
            parse_verb(LevelBinary, LineNumber, State);
        [Name | _Args] ->
            reject_unknown_or_forbidden(Name, LineNumber);
        [] ->
            {ok, State}
    end.

parse_remote(Host, PortBinary, LineNumber, State) ->
    case parse_decimal_integer(PortBinary) of
        {ok, Port} ->
            case vpn_ovpn_envelope:validate_remote(Host, Port) of
                ok ->
                    put_singleton(remote, #{host => Host, port => Port},
                                  LineNumber, State);
                {error, Reason} ->
                    {error, {line, LineNumber, Reason}}
            end;
        error ->
            {error, {line, LineNumber, invalid_remote_port}}
    end.

parse_verb(LevelBinary, LineNumber, State) ->
    case parse_decimal_integer(LevelBinary) of
        {ok, Level} when Level >= 0, Level =< 11 ->
            put_option(verb, Level, LineNumber, State);
        _ ->
            {error, {line, LineNumber, invalid_verb_level}}
    end.

reject_unknown_or_forbidden(Name, LineNumber) ->
    Forbidden = vpn_ovpn_envelope:forbidden_directives(),
    case lists:member(Name, Forbidden) of
        true -> {error, {line, LineNumber, {forbidden_directive, Name}}};
        false -> {error, {line, LineNumber, {unknown_directive, Name}}}
    end.

put_singleton(Name, Value, LineNumber, State) ->
    case mark_seen(Name, LineNumber, State) of
        {ok, State1} -> {ok, put_value(Name, Value, State1)};
        {error, _} = Error -> Error
    end.

put_option(Name, Value, LineNumber, State) ->
    case mark_seen(Name, LineNumber, State) of
        {ok, State1} ->
            Options = maps:get(options, State1),
            {ok, State1#{options := Options#{Name => Value}}};
        {error, _} = Error ->
            Error
    end.

mark_seen(Name, LineNumber, State) ->
    Seen = maps:get(seen, State),
    case maps:is_key(Name, Seen) of
        true ->
            {error, {line, LineNumber, {duplicate_directive, Name}}};
        false ->
            {ok, State#{seen := Seen#{Name => LineNumber}}}
    end.

put_value(Name, Value, State) ->
    Values = maps:get(values, State),
    State#{values := Values#{Name => Value}}.

finalize(State) ->
    Seen = maps:get(seen, State),
    Required = [client, dev, proto, remote, ca, cert, key],
    Missing = [Name || Name <- Required, not maps:is_key(Name, Seen)],
    case Missing of
        [] ->
            Values = maps:get(values, State),
            Remote = maps:get(remote, Values),
            Options0 = maps:get(options, State),
            Options = #{nobind => maps:get(nobind, Options0, false),
                        persist_key => maps:get(persist_key, Options0, false),
                        persist_tun => maps:get(persist_tun, Options0, false),
                        remote_cert_tls => maps:get(remote_cert_tls, Options0, undefined),
                        verb => maps:get(verb, Options0, undefined)},
            {ok, #{contract => vpn_ovpn_envelope:version(),
                   mode => client,
                   tunnel_device => tun,
                   transport => udp,
                   remote_host => maps:get(host, Remote),
                   remote_port => maps:get(port, Remote),
                   ca_pem => maps:get(ca, Values),
                   certificate_pem => maps:get(cert, Values),
                   private_key_ref => maps:get(key, Values),
                   options => Options}};
        _ ->
            {error, {missing_required_entries, Missing}}
    end.

validate_certificate_block(Name, Pem) ->
    case byte_size(Pem) of
        0 ->
            {error, {empty_block, Name}};
        _ ->
            case binary:match(Pem, <<"PRIVATE KEY">>) of
                {_, _} ->
                    {error, private_key_material_forbidden};
                nomatch ->
                    validate_single_certificate_pem(Name, Pem)
            end
    end.

validate_single_certificate_pem(Name, Pem) ->
    Begin = binary:matches(Pem, <<"-----BEGIN CERTIFICATE-----">>),
    End = binary:matches(Pem, <<"-----END CERTIFICATE-----">>),
    case {length(Begin), length(End)} of
        {1, 1} -> ok;
        _ -> {error, {invalid_certificate_block, Name}}
    end.

block_binary(Lines) ->
    iolist_to_binary([lists:join(<<"\n">>, Lines), <<"\n">>]).

whitespace_tokens(Binary) ->
    [list_to_binary(Token) || Token <- string:tokens(binary_to_list(Binary), " \t")].

parse_decimal_integer(Binary) ->
    try binary_to_integer(Binary) of
        Integer -> {ok, Integer}
    catch
        error:badarg -> error
    end.

trim(Binary) ->
    trim_right(trim_left(Binary)).

trim_left(<<Byte, Rest/binary>>) when Byte =:= 32; Byte =:= 9 ->
    trim_left(Rest);
trim_left(Binary) ->
    Binary.

trim_right(<<>>) ->
    <<>>;
trim_right(Binary) ->
    Size = byte_size(Binary),
    case binary:at(Binary, Size - 1) of
        Byte when Byte =:= 32; Byte =:= 9 ->
            trim_right(binary:part(Binary, 0, Size - 1));
        _ ->
            Binary
    end.
