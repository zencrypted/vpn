%%%-------------------------------------------------------------------
%% @doc KVS/Mnesia backend for the durable VPN projection.
%%
%% KVS owns schema registration while this adapter uses an explicit Mnesia
%% transaction to provide compare-and-set semantics for the single projection
%% record.
%%%-------------------------------------------------------------------
-module(vpn_projection_store_kvs).

-behaviour(vpn_projection_store).

-export([load/0, commit/2]).

-include("vpn_projection.hrl").

load() ->
    case mnesia:transaction(
           fun() ->
                   mnesia:read(vpn_projection, current, read)
           end) of
        {atomic, []} ->
            not_found;
        {atomic, [Record = #vpn_projection{}]} ->
            Envelope = record_to_envelope(Record),
            {ok, Record#vpn_projection.projection_version, Envelope};
        {atomic, [_InvalidRecord]} ->
            {error, invalid_projection_record};
        {atomic, Records} ->
            {error, {invalid_projection_record_count, length(Records)}};
        {aborted, Reason} ->
            {error, {mnesia_load_failed, Reason}}
    end.

commit(ExpectedVersion, Envelope)
  when is_integer(ExpectedVersion), ExpectedVersion >= 0, is_map(Envelope) ->
    case envelope_to_record(ExpectedVersion, Envelope) of
        {ok, Record = #vpn_projection{projection_version = NewVersion}} ->
            case mnesia:sync_transaction(
                   fun() ->
                           commit_record(ExpectedVersion, Record)
                   end) of
                {atomic, ok} ->
                    {ok, NewVersion};
                {aborted, conflict} ->
                    {error, conflict};
                {aborted, Reason} ->
                    {error, {mnesia_commit_failed, Reason}}
            end;
        {error, Reason} ->
            {error, Reason}
    end;
commit(_ExpectedVersion, _Envelope) ->
    {error, invalid_commit_arguments}.

commit_record(0, Record) ->
    case mnesia:read(vpn_projection, current, write) of
        [] ->
            mnesia:write(Record),
            ok;
        [_] ->
            mnesia:abort(conflict)
    end;
commit_record(ExpectedVersion, Record) ->
    case mnesia:read(vpn_projection, current, write) of
        [#vpn_projection{projection_version = ExpectedVersion}] ->
            mnesia:write(Record),
            ok;
        _ ->
            mnesia:abort(conflict)
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
