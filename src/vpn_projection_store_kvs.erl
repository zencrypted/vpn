%%%-------------------------------------------------------------------
%% @doc KVS backend for the durable VPN projection.
%%
%% KVS owns schema registration and record access. The configured VPN
%% transaction provider owns the compare-and-set boundary, so this store does
%% not depend on a concrete database backend.
%%%-------------------------------------------------------------------
-module(vpn_projection_store_kvs).

-behaviour(vpn_projection_store).

-export([load/0, commit/2]).

-include("vpn_projection.hrl").

load() ->
    case vpn_kvs_transaction:ensure() of
        ok -> load_record();
        {error, _} = Error -> Error
    end.

commit(ExpectedVersion, Envelope)
  when is_integer(ExpectedVersion), ExpectedVersion >= 0, is_map(Envelope) ->
    case envelope_to_record(ExpectedVersion, Envelope) of
        {ok, Record = #vpn_projection{projection_version = NewVersion}} ->
            case vpn_kvs_transaction:run(
                   fun() -> commit_record(ExpectedVersion, Record) end) of
                {ok, ok} ->
                    {ok, NewVersion};
                {error, conflict} ->
                    {error, conflict};
                {error, Reason} ->
                    {error, {kvs_commit_failed, Reason}}
            end;
        {error, Reason} ->
            {error, Reason}
    end;
commit(_ExpectedVersion, _Envelope) ->
    {error, invalid_commit_arguments}.

load_record() ->
    case catch kvs:get(vpn_projection, current) of
        {error, not_found} ->
            not_found;
        {ok, Record = #vpn_projection{}} ->
            Envelope = record_to_envelope(Record),
            {ok, Record#vpn_projection.projection_version, Envelope};
        {ok, _InvalidRecord} ->
            {error, invalid_projection_record};
        {error, Reason} ->
            {error, {kvs_load_failed, Reason}};
        {'EXIT', Reason} ->
            {error, {kvs_load_failed, Reason}};
        Other ->
            {error, {invalid_projection_load_result, Other}}
    end.

commit_record(0, Record) ->
    case get_record_in_transaction() of
        not_found ->
            put_record_in_transaction(Record);
        {ok, #vpn_projection{}} ->
            vpn_kvs_transaction:abort(conflict);
        {error, Reason} ->
            vpn_kvs_transaction:abort(Reason)
    end;
commit_record(ExpectedVersion, Record) ->
    case get_record_in_transaction() of
        {ok, #vpn_projection{projection_version = ExpectedVersion}} ->
            put_record_in_transaction(Record);
        not_found ->
            vpn_kvs_transaction:abort(conflict);
        {ok, #vpn_projection{}} ->
            vpn_kvs_transaction:abort(conflict);
        {error, Reason} ->
            vpn_kvs_transaction:abort(Reason)
    end.

get_record_in_transaction() ->
    case catch kvs:get(vpn_projection, current) of
        {ok, Record = #vpn_projection{}} -> {ok, Record};
        {ok, Invalid} -> {error, {invalid_projection_record, Invalid}};
        {error, not_found} -> not_found;
        {error, Reason} -> {error, {kvs_projection_read_failed, Reason}};
        {'EXIT', Reason} -> {error, {kvs_projection_read_failed, Reason}};
        Other -> {error, {invalid_projection_read_result, Other}}
    end.

put_record_in_transaction(Record) ->
    case catch kvs:put(Record) of
        ok -> ok;
        {error, Reason} ->
            vpn_kvs_transaction:abort(
              {kvs_projection_write_failed, Reason});
        {'EXIT', Reason} ->
            vpn_kvs_transaction:abort(
              {kvs_projection_write_failed, Reason});
        Other ->
            vpn_kvs_transaction:abort(
              {invalid_projection_write_result, Other})
    end.

envelope_to_record(ExpectedVersion,
                   #{schema_version := SchemaVersion,
                     projection_version := NewVersion,
                     checksum := Checksum,
                     payload := Payload,
                     updated_at := UpdatedAt})
  when is_integer(SchemaVersion), SchemaVersion > 0,
       NewVersion =:= ExpectedVersion + 1,
       is_binary(Checksum), byte_size(Checksum) =:= 32,
       is_map(Payload),
       is_integer(UpdatedAt), UpdatedAt >= 0 ->
    {ok, #vpn_projection{id = current,
                         schema_version = SchemaVersion,
                         projection_version = NewVersion,
                         checksum = Checksum,
                         payload = Payload,
                         updated_at = UpdatedAt}};
envelope_to_record(_ExpectedVersion, _Envelope) ->
    {error, invalid_projection_envelope}.

record_to_envelope(#vpn_projection{schema_version = SchemaVersion,
                                    projection_version = ProjectionVersion,
                                    checksum = Checksum,
                                    payload = Payload,
                                    updated_at = UpdatedAt}) ->
    #{schema_version => SchemaVersion,
      projection_version => ProjectionVersion,
      checksum => Checksum,
      payload => Payload,
      updated_at => UpdatedAt}.
