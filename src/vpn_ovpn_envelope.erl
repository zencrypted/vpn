%%%-------------------------------------------------------------------
%% @doc Machine-readable constants and semantic validation for the
%% canonical Zencrypted OVPN envelope contract.
%%
%% This module does not parse OpenVPN configuration files and does not
%% implement the OpenVPN wire protocol. It defines the values that the
%% future canonical envelope importer must enforce.
%%%-------------------------------------------------------------------
-module(vpn_ovpn_envelope).

-export([contract/0,
         version/0,
         runtime/0,
         profiles/0,
         two_factor_modes/0,
         required_directives/0,
         optional_directives/0,
         forbidden_directives/0,
         validate_metadata/1,
         validate_key_reference/1,
         validate_remote/2]).

-spec contract() -> map().
contract() ->
    #{version => version(),
      runtime => runtime(),
      profiles => profiles(),
      two_factor_modes => two_factor_modes(),
      required_metadata => [envelope, runtime, profile, two_factor],
      conditional_metadata => #{<<"device-bound">> => [device_id]},
      optional_metadata => [provisioning_id, certificate_sha256],
      required_directives => required_directives(),
      optional_directives => optional_directives(),
      forbidden_directives => forbidden_directives()}.

-spec version() -> binary().
version() ->
    <<"ovpn/v1">>.

-spec runtime() -> binary().
runtime() ->
    <<"zencrypted-overlay">>.

-spec profiles() -> [binary()].
profiles() ->
    [<<"portable">>, <<"device-bound">>].

-spec two_factor_modes() -> [binary()].
two_factor_modes() ->
    [<<"disabled">>, <<"optional">>, <<"required">>].

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

-spec validate_metadata(map()) -> ok | {error, term()}.
validate_metadata(Metadata) when is_map(Metadata) ->
    Validators = [fun validate_known_metadata_keys/1,
                  fun validate_required_metadata/1,
                  fun validate_profile_metadata/1,
                  fun validate_optional_metadata/1],
    run_validators(Validators, Metadata);
validate_metadata(_Metadata) ->
    {error, invalid_metadata}.

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


run_validators([], _Metadata) ->
    ok;
run_validators([Validator | Rest], Metadata) ->
    case Validator(Metadata) of
        ok ->
            run_validators(Rest, Metadata);
        {error, _Reason} = Error ->
            Error
    end.

validate_known_metadata_keys(Metadata) ->
    Allowed = [envelope,
               runtime,
               profile,
               device_id,
               two_factor,
               provisioning_id,
               certificate_sha256],
    case [Key || Key <- maps:keys(Metadata), not lists:member(Key, Allowed)] of
        [] ->
            ok;
        [Unknown | _] ->
            {error, {unknown_metadata, Unknown}}
    end.

validate_required_metadata(Metadata) ->
    Required = [{envelope, version()},
                {runtime, runtime()}],
    case validate_exact_values(Metadata, Required) of
        ok ->
            validate_member_value(Metadata, profile, profiles());
        {error, _Reason} = Error ->
            Error
    end.

validate_exact_values(Metadata, []) ->
    validate_member_value(Metadata, two_factor, two_factor_modes());
validate_exact_values(Metadata, [{Key, Expected} | Rest]) ->
    case maps:find(Key, Metadata) of
        {ok, Expected} ->
            validate_exact_values(Metadata, Rest);
        {ok, Actual} ->
            {error, {unsupported_metadata_value, Key, Actual}};
        error ->
            {error, {missing_metadata, Key}}
    end.

validate_member_value(Metadata, Key, Allowed) ->
    case maps:find(Key, Metadata) of
        {ok, Value} ->
            case lists:member(Value, Allowed) of
                true ->
                    ok;
                false ->
                    {error, {unsupported_metadata_value, Key, Value}}
            end;
        error ->
            {error, {missing_metadata, Key}}
    end.

validate_profile_metadata(#{profile := <<"device-bound">>} = Metadata) ->
    case maps:find(device_id, Metadata) of
        {ok, DeviceId} ->
            validate_metadata_token(device_id, DeviceId);
        error ->
            {error, {missing_metadata, device_id}}
    end;
validate_profile_metadata(#{profile := <<"portable">>} = Metadata) ->
    case maps:is_key(device_id, Metadata) of
        true ->
            {error, {unexpected_metadata, device_id}};
        false ->
            ok
    end;
validate_profile_metadata(_Metadata) ->
    {error, {missing_metadata, profile}}.


validate_optional_metadata(Metadata) ->
    case validate_optional_token(Metadata, provisioning_id) of
        ok ->
            validate_optional_fingerprint(Metadata);
        {error, _Reason} = Error ->
            Error
    end.

validate_optional_token(Metadata, Key) ->
    case maps:find(Key, Metadata) of
        error ->
            ok;
        {ok, Value} ->
            validate_metadata_token(Key, Value)
    end.

validate_optional_fingerprint(Metadata) ->
    case maps:find(certificate_sha256, Metadata) of
        error ->
            ok;
        {ok, Fingerprint} ->
            validate_sha256_fingerprint(Fingerprint)
    end.

validate_sha256_fingerprint(Fingerprint)
  when is_binary(Fingerprint), byte_size(Fingerprint) =:= 64 ->
    case lists:all(fun is_hex_digit/1, binary_to_list(Fingerprint)) of
        true ->
            ok;
        false ->
            {error, {invalid_metadata_value, certificate_sha256}}
    end;
validate_sha256_fingerprint(_Fingerprint) ->
    {error, {invalid_metadata_value, certificate_sha256}}.

is_hex_digit(Byte) when Byte >= $0, Byte =< $9 ->
    true;
is_hex_digit(Byte) when Byte >= $A, Byte =< $F ->
    true;
is_hex_digit(Byte) when Byte >= $a, Byte =< $f ->
    true;
is_hex_digit(_Byte) ->
    false.

validate_metadata_token(Key, Value)
  when is_binary(Value), byte_size(Value) > 0, byte_size(Value) =< 255 ->
    case lists:all(fun is_safe_token_character/1, binary_to_list(Value)) of
        true ->
            ok;
        false ->
            {error, {invalid_metadata_value, Key}}
    end;
validate_metadata_token(Key, _Value) ->
    {error, {invalid_metadata_value, Key}}.

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
                    validate_key_reference_segments(binary:split(Reference, <<"/">>, [global]))
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
