%%%-------------------------------------------------------------------
%% @doc Explicit migration of legacy ETF-dependent projection checksums.
%%
%% Migration is never performed during application boot. A checksum that can
%% still be verified on the current OTP release may be migrated with
%% migrate_legacy_checksum/0. Cross-OTP records whose legacy checksum no
%% longer verifies require the deliberately explicit confirmation atom used by
%% migrate_legacy_checksum/1 after the operator has backed up the Mnesia data.
%%%-------------------------------------------------------------------
-module(vpn_projection_migration).

-export([inspect/0,
         migrate_legacy_checksum/0,
         migrate_legacy_checksum/1]).

-define(LEGACY_SCHEMA_VERSION, 1).
-define(CURRENT_SCHEMA_VERSION, 2).

inspect() ->
    case vpn_projection_store_kvs:load() of
        not_found -> {ok, empty};
        {ok, Version, #{schema_version := ?CURRENT_SCHEMA_VERSION}} ->
            {ok, #{state => current, projection_version => Version}};
        {ok, Version, #{schema_version := ?LEGACY_SCHEMA_VERSION} = Envelope} ->
            {ok, #{state => legacy,
                   projection_version => Version,
                   legacy_checksum_valid => legacy_checksum_valid(Envelope)}};
        {ok, _Version, #{schema_version := SchemaVersion}} ->
            {error, {unsupported_schema_version, SchemaVersion}};
        {error, _} = Error -> Error;
        Other -> {error, {invalid_projection_load_result, Other}}
    end.

migrate_legacy_checksum() ->
    migrate(verified_only).

migrate_legacy_checksum(accept_unverifiable_legacy_checksum) ->
    migrate(allow_unverifiable);
migrate_legacy_checksum(_Confirmation) ->
    {error, invalid_migration_confirmation}.

migrate(Mode) ->
    case whereis(vpn_projection) of
        undefined -> migrate_stopped_projection(Mode);
        _Pid -> {error, projection_must_be_stopped}
    end.

migrate_stopped_projection(Mode) ->
    case vpn_projection_store_kvs:load() of
        not_found -> {ok, empty};
        {ok, Version, #{schema_version := ?CURRENT_SCHEMA_VERSION}} ->
            {ok, #{state => already_current,
                   projection_version => Version}};
        {ok, Version,
         #{schema_version := ?LEGACY_SCHEMA_VERSION,
           projection_version := Version,
           checksum := Checksum,
           payload := Projection,
           updated_at := UpdatedAt} = Envelope}
          when is_binary(Checksum), byte_size(Checksum) =:= 32,
               is_integer(Version), Version > 0,
               is_integer(UpdatedAt), UpdatedAt >= 0 ->
            case vpn_projection:validate_payload(Projection) of
                ok -> migrate_valid_legacy(Mode, Version, Projection,
                                           UpdatedAt, Envelope);
                {error, Reason} -> {error, Reason}
            end;
        {ok, _Version, #{schema_version := ?LEGACY_SCHEMA_VERSION}} ->
            {error, invalid_projection_envelope};
        {ok, _Version, #{schema_version := SchemaVersion}} ->
            {error, {unsupported_schema_version, SchemaVersion}};
        {error, _} = Error -> Error;
        Other -> {error, {invalid_projection_load_result, Other}}
    end.

migrate_valid_legacy(verified_only, Version, Projection, UpdatedAt, Envelope) ->
    case legacy_checksum_valid(Envelope) of
        true -> rewrite_current(Version, Projection, UpdatedAt, verified);
        false -> {error, legacy_checksum_not_verifiable_on_this_otp}
    end;
migrate_valid_legacy(allow_unverifiable, Version, Projection, UpdatedAt,
                     Envelope) ->
    Verification = case legacy_checksum_valid(Envelope) of
                       true -> verified;
                       false -> operator_accepted_unverifiable
                   end,
    rewrite_current(Version, Projection, UpdatedAt, Verification).

rewrite_current(Version, Projection, UpdatedAt, Verification) ->
    Envelope = vpn_projection:build_envelope(Version, Projection, UpdatedAt),
    case vpn_projection_store_kvs:rewrite(Version, Envelope) of
        {ok, Version} ->
            {ok, #{state => migrated,
                   projection_version => Version,
                   legacy_verification => Verification}};
        {error, _} = Error -> Error;
        Other -> {error, {invalid_projection_rewrite_result, Other}}
    end.

legacy_checksum_valid(#{schema_version := ?LEGACY_SCHEMA_VERSION,
                        projection_version := Version,
                        checksum := Checksum,
                        payload := Projection,
                        updated_at := UpdatedAt}) ->
    Expected = vpn_projection_checksum:legacy_checksum(
                 ?LEGACY_SCHEMA_VERSION, Version, Projection, UpdatedAt),
    secure_equal(Checksum, Expected);
legacy_checksum_valid(_Envelope) ->
    false.

secure_equal(Left, Right)
  when is_binary(Left), is_binary(Right), byte_size(Left) =:= byte_size(Right) ->
    secure_equal(Left, Right, 0) =:= 0;
secure_equal(_Left, _Right) ->
    false.

secure_equal(<<>>, <<>>, Acc) ->
    Acc;
secure_equal(<<Left, LeftRest/binary>>, <<Right, RightRest/binary>>, Acc) ->
    secure_equal(LeftRest, RightRest, Acc bor (Left bxor Right)).
