%%%-------------------------------------------------------------------
%% @doc Machine-readable constants and semantic validation for the
%% canonical OVPN envelope subset consumed by this VPN runtime.
%%
%% The contract intentionally uses ordinary OVPN syntax only. It does
%% not define vendor-prefixed directives or comment metadata, and it
%% does not implement the OpenVPN wire protocol.
%%%-------------------------------------------------------------------
-module(vpn_ovpn_envelope).

-export([contract/0,
         version/0,
         required_directives/0,
         optional_directives/0,
         forbidden_directives/0,
         validate_key_reference/1,
         validate_remote/2]).

-spec contract() -> map().
contract() ->
    #{version => version(),
      serialized_version => false,
      custom_metadata => none,
      security_policy => external,
      required_directives => required_directives(),
      optional_directives => optional_directives(),
      forbidden_directives => forbidden_directives()}.

%% The version identifies this documented/parser contract. It is not
%% serialized into the OVPN file.
-spec version() -> binary().
version() ->
    <<"ovpn/v1">>.

-spec required_directives() -> [binary()].
required_directives() ->
    [<<"client">>,
     <<"dev">>,
     <<"proto">>,
     <<"remote">>,
     <<"<ca>">>,
     <<"<cert>">>,
     <<"key">>].

-spec optional_directives() -> [binary()].
optional_directives() ->
    [<<"nobind">>,
     <<"persist-key">>,
     <<"persist-tun">>,
     <<"remote-cert-tls">>,
     <<"verb">>].

-spec forbidden_directives() -> [binary()].
forbidden_directives() ->
    [<<"<key>">>,
     <<"auth-user-pass">>,
     <<"askpass">>,
     <<"plugin">>,
     <<"script-security">>,
     <<"up">>,
     <<"down">>,
     <<"management">>,
     <<"tls-auth">>,
     <<"tls-crypt">>,
     <<"secret">>,
     <<"pkcs12">>].

-spec validate_key_reference(binary()) -> ok | {error, term()}.
validate_key_reference(Reference)
  when is_binary(Reference), byte_size(Reference) > 0, byte_size(Reference) =< 1024 ->
    case unsafe_key_reference(Reference) of
        false ->
            ok;
        Reason ->
            {error, Reason}
    end;
validate_key_reference(Reference) when is_binary(Reference) ->
    {error, invalid_key_reference_length};
validate_key_reference(_Reference) ->
    {error, invalid_key_reference}.

-spec validate_remote(binary(), integer()) -> ok | {error, term()}.
validate_remote(Host, _Port) when not is_binary(Host); Host =:= <<>> ->
    {error, invalid_remote_host};
validate_remote(_Host, Port)
  when not is_integer(Port); Port < 1; Port > 65535 ->
    {error, invalid_remote_port};
validate_remote(Host, _Port) ->
    case contains_control_or_space(Host) orelse
         binary:match(Host, <<"/">>) =/= nomatch orelse
         binary:match(Host, <<"\\">>) =/= nomatch of
        true ->
            {error, invalid_remote_host};
        false ->
            ok
    end.

unsafe_key_reference(<<"/", _/binary>>) ->
    absolute_key_reference;
unsafe_key_reference(Reference) ->
    case binary:match(Reference, <<"\\">>) of
        {_, _} ->
            invalid_key_reference_separator;
        nomatch ->
            case contains_control_or_space(Reference) of
                true ->
                    invalid_key_reference_character;
                false ->
                    validate_key_reference_segments(
                      binary:split(Reference, <<"/">>, [global]))
            end
    end.

validate_key_reference_segments([]) ->
    invalid_key_reference;
validate_key_reference_segments(Segments) ->
    case lists:any(fun invalid_path_segment/1, Segments) of
        true ->
            unsafe_key_reference_segment;
        false ->
            false
    end.

invalid_path_segment(<<>>) ->
    true;
invalid_path_segment(<<".">>) ->
    true;
invalid_path_segment(<<"..">>) ->
    true;
invalid_path_segment(Segment) ->
    not lists:all(fun is_safe_token_character/1, binary_to_list(Segment)).

is_safe_token_character(Byte) when Byte >= $a, Byte =< $z ->
    true;
is_safe_token_character(Byte) when Byte >= $A, Byte =< $Z ->
    true;
is_safe_token_character(Byte) when Byte >= $0, Byte =< $9 ->
    true;
is_safe_token_character($.) ->
    true;
is_safe_token_character($_) ->
    true;
is_safe_token_character($-) ->
    true;
is_safe_token_character(_Byte) ->
    false.

contains_control_or_space(Binary) ->
    lists:any(fun(Byte) -> Byte =< 32 orelse Byte =:= 127 end,
              binary_to_list(Binary)).
