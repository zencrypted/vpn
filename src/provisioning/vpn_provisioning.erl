%%%-------------------------------------------------------------------
%% @doc Revisioned IAS-to-VPN provisioning command contract.
%%
%% Commands are serialized by this process. Revisions are monotonic per peer,
%% duplicate delivery is idempotent, and accepted heads are stored in the
%% durable VPN projection so revoke/remove barriers survive process and node
%% restart. Validated heads are also exposed to startup runtime recovery before
%% peer supervision begins.
%%%-------------------------------------------------------------------
-module(vpn_provisioning).
-behaviour(gen_server).

-export([start_link/0, apply/1, apply_dynamic/2, decommission_orphan/1,
         status/0, history/1, recovery_heads/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(HISTORY_LIMIT, 50).
-define(PROVISIONING_SCHEMA_VERSION, 2).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

apply(Command) ->
    gen_server:call(?SERVER, {apply, Command}, infinity).

%% @doc Apply a revisioned dynamic-pair upsert as one serialized operation.
%%
%% The Device identifier is bound into the command digest. The dynamic pair is
%% materialized, written with its final revision metadata, and established
%% between a durable pending barrier and the final applied head. Ordinary
%% apply/1 remains available for static peers and compatibility with the former
%% two-step flow.
apply_dynamic(DeviceId, Command) ->
    gen_server:call(?SERVER, {apply_dynamic, DeviceId, Command}, infinity).

%% @doc Compare and remove an IAS-owned orphan from VPN.
%%
%% The caller supplies a fresh, non-secret snapshot selector. The operation
%% fails closed when the durable heads, registry ownership, peer set, or
%% allocator identity changed after that snapshot was produced. Successful
%% retries are idempotent.
-spec decommission_orphan(map()) -> {ok, map()} | {error, term()}.
decommission_orphan(Request) when is_map(Request) ->
    gen_server:call(?SERVER, {decommission_orphan, Request}, infinity);
decommission_orphan(_Request) ->
    {error, invalid_orphan_decommission_request}.

status() ->
    gen_server:call(?SERVER, status).

history(PeerId) ->
    gen_server:call(?SERVER, {history, PeerId}).

init([]) ->
    case restore_heads() of
        {ok, Heads} ->
            {ok, #{heads => Heads,
                   history => #{},
                   commands_received => 0,
                   commands_applied => 0,
                   commands_unchanged => 0,
                   commands_rejected => 0,
                   stale_revisions => 0,
                   revocations => 0,
                   last_command => undefined,
                   last_result => undefined}};
        {error, Reason} ->
            {stop, {provisioning_projection_restore_failed, Reason}}
    end.

handle_call(status, _From, State) ->
    {reply, provisioning_status(State), State};
handle_call({history, PeerId}, _From, State) ->
    {reply, maps:get(PeerId, maps:get(history, State), []), State};
handle_call({apply, Command}, _From, State0) ->
    State1 = increment_received(State0),
    case validate_command(Command) of
        {ok, Normalized} ->
            {Reply, State2} = apply_validated(Normalized, State1),
            {reply, Reply, State2};
        {error, Reason} ->
            Result = {error, Reason},
            {reply, Result, record_rejected(Command, Result, State1)}
    end;
handle_call({apply_dynamic, DeviceId, Command}, _From, State0) ->
    State1 = increment_received(State0),
    case validate_dynamic_command(DeviceId, Command) of
        {ok, Normalized} ->
            {Reply, State2} = apply_dynamic_validated(Normalized, State1),
            {reply, Reply, State2};
        {error, Reason} ->
            Result = {error, Reason},
            {reply, Result, record_rejected(Command, Result, State1)}
    end;
handle_call({decommission_orphan, Request}, _From, State0) ->
    case normalize_orphan_decommission_request(Request) of
        {ok, Normalized} ->
            {Reply, State1} = decommission_orphan_validated(Normalized, State0),
            {reply, Reply, State1};
        {error, Reason} ->
            {reply, {error, Reason}, State0}
    end;
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_operation}, State}.

handle_cast(_Message, State) -> {noreply, State}.
handle_info(_Message, State) -> {noreply, State}.

increment_received(State) ->
    State#{commands_received => maps:get(commands_received, State) + 1}.

apply_validated(Command, State) ->
    apply_validated(Command, State, fun prepare_command/1).

apply_dynamic_validated(Command, State) ->
    apply_validated(Command, State, fun prepare_dynamic_command/1).

apply_validated(Command = #{peer_id := PeerId, revision := Revision}, State,
                Preparer) ->
    Heads = maps:get(heads, State),
    Head = maps:get(PeerId, Heads, bootstrap_head(PeerId)),
    CurrentRevision = maps:get(revision, Head),
    Digest = command_digest(Command),
    LegacyDigest = legacy_command_digest(Command),
    case Revision of
        R when R < CurrentRevision ->
            Result = {error, stale_revision},
            {Result, record_stale(Command, Result, State)};
        R when R =:= CurrentRevision ->
            apply_current_revision(Command, Digest, LegacyDigest, Head, State, Preparer);
        _ ->
            case validate_transition(Command, Head) of
                ok -> prepare_new_revision(Command, Digest, Head, State, Preparer);
                {error, Reason} ->
                    Result = {error, Reason},
                    {Result, record_rejected(Command, Result, State)}
            end
    end.

apply_current_revision(Command, Digest, LegacyDigest, Head, State, Preparer) ->
    DigestVersion = maps:get(digest_version, Head, 1),
    HeadDigest = maps:get(digest, Head, undefined),
    Phase = maps:get(phase, Head, applied),
    SchemaVer = vpn_provisioning_command_digest:schema_version(),
    case {DigestVersion, HeadDigest, Phase} of
        {Version, Digest, applied}
          when Version =:= SchemaVer ->
            Result = {ok, unchanged},
            {Result, record_unchanged(Command, Result, State)};
        {Version, Digest, pending}
          when Version =:= SchemaVer ->
            resume_pending(Command, Digest, Head, State, Preparer);
        {1, LegacyDigest, LegacyPhase} ->
            case migrate_legacy_head(Command, Digest, Head, State) of
                {ok, MigratedState, _MigratedHead} when LegacyPhase =:= applied ->
                    Result = {ok, unchanged},
                    {Result, record_unchanged(Command, Result, MigratedState)};
                {ok, MigratedState, MigratedHead} when LegacyPhase =:= pending ->
                    resume_pending(Command, Digest, MigratedHead,
                                   MigratedState, Preparer);
                {error, Reason} ->
                    Result = {error, Reason},
                    {Result, record_rejected(Command, Result, State)}
            end;
        {_OtherVersion, _OtherDigest, _Phase} ->
            Result = {error, revision_conflict},
            {Result, record_rejected(Command, Result, State)}
    end.

prepare_new_revision(Command, Digest, Head, State, Preparer) ->
    case Preparer(Command) of
        {ok, Plan} ->
            case persist_command_phase(Command,
                                       Digest,
                                       pending,
                                       Head,
                                       State) of
                {ok, PendingState} ->
                    execute_and_finalize(Command,
                                         Digest,
                                         Plan,
                                         PendingState);
                {error, Reason} ->
                    Result = {error, Reason},
                    {Result, record_rejected(Command, Result, State)}
            end;
        {error, Reason} ->
            Result = {error, Reason},
            {Result, record_rejected(Command, Result, State)}
    end.

resume_pending(Command, Digest, _Head, State, Preparer) ->
    case Preparer(Command) of
        {ok, Plan} ->
            execute_and_finalize(Command, Digest, Plan, State);
        {error, Reason} ->
            Result = {error, Reason},
            {Result, record_rejected(Command, Result, State)}
    end.

execute_and_finalize(Command, Digest, Plan, State) ->
    PeerId = maps:get(peer_id, Command),
    PendingHead = maps:get(PeerId, maps:get(heads, State)),
    case execute_plan(Plan) of
        {ok, Outcome} ->
            case persist_command_phase(Command,
                                       Digest,
                                       applied,
                                       PendingHead,
                                       State) of
                {ok, AppliedState} ->
                    Result = {ok, Outcome},
                    {Result, record_applied(Command, Result, AppliedState)};
                {error, Reason} ->
                    Result = {error,
                              {provisioning_ledger_finalize_failed, Reason}},
                    {Result, record_rejected(Command, Result, State)}
            end;
        {error, Reason} ->
            %% The durable pending head intentionally remains. Re-delivery of
            %% the same revision/digest retries the idempotent runtime action;
            %% newer revisions are blocked until that recovery completes.
            Result = {error, Reason},
            {Result, record_rejected(Command, Result, State)}
    end.

validate_transition(#{operation := enable},
                    #{lifecycle_state := revoked}) ->
    {error, revoked};
validate_transition(_Command, #{phase := pending}) ->
    {error, provisioning_recovery_required};
validate_transition(_Command, _Head) ->
    ok.

prepare_dynamic_command(#{dynamic_device_id := DeviceId,
                          operation := upsert,
                          peer_id := PeerId,
                          revision := Revision,
                          source := Source,
                          desired_state := Desired}) ->
    case vpn_peer_allocator:lookup(DeviceId) of
        {ok, Allocation} ->
            ExpectedPeerId = maps:get(client_peer_id, Allocation),
            case PeerId =:= ExpectedPeerId of
                true ->
                    Metadata = #{revision => Revision,
                                 source => Source,
                                 operation => upsert},
                    RuntimeDesired = maps:remove(recovery_manifest, Desired),
                    {ok, {dynamic_upsert, DeviceId, RuntimeDesired, Metadata}};
                false ->
                    {error, {dynamic_pair_client_peer_mismatch,
                             ExpectedPeerId,
                             PeerId}}
            end;
        {error, not_found} ->
            {error, {dynamic_peer_allocation_required, DeviceId}};
        {error, _} = Error ->
            Error
    end.

prepare_command(#{operation := remove, peer_id := PeerId}) ->
    {ok, {remove, PeerId}};
prepare_command(Command = #{operation := Operation,
                            peer_id := PeerId,
                            revision := Revision,
                            source := Source}) ->
    Desired = maps:get(desired_state, Command, #{}),
    RuntimeDesired = maps:remove(recovery_manifest, Desired),
    case base_config(PeerId, RuntimeDesired) of
        {ok, BaseConfig} ->
            case next_config(Operation, BaseConfig, RuntimeDesired) of
                {ok, Next0} ->
                    Now = erlang:system_time(second),
                    Next = Next0#{id => PeerId,
                                  revision => Revision,
                                  provisioning_source => Source,
                                  last_provisioning_operation => Operation,
                                  updated_at => Now},
                    {ok, {config, Operation, PeerId, BaseConfig, Next}};
                {error, _} = Error -> Error
            end;
        {error, _} = Error -> Error
    end.

execute_plan({dynamic_upsert, DeviceId, Desired, Metadata}) ->
    case vpn_dynamic_pair:provision(DeviceId, Desired, Metadata) of
        {ok, PairStatus} ->
            {ok, #{operation => upsert, pair => PairStatus}};
        {error, _} = Error ->
            Error
    end;
execute_plan({remove, PeerId}) ->
    case vpn_peer_registry:remove(PeerId) of
        ok -> {ok, removed};
        {error, not_found} -> {ok, removed}
    end;
execute_plan({config, Operation, PeerId, BaseConfig, Next}) ->
    persist_next_config(Operation, PeerId, BaseConfig, Next).

base_config(PeerId, Desired) ->
    case vpn_peer_registry:config(PeerId) of
        {ok, Config} -> {ok, Config};
        {error, not_found} ->
            case maps:get(runtime_config, Desired, undefined) of
                Runtime when is_map(Runtime) -> {ok, Runtime#{id => PeerId}};
                _ -> vpn_runtime_config_resolver:resolve(PeerId, Desired)
            end
    end.

next_config(upsert, Base, Desired) ->
    Runtime = maps:get(runtime_config, Desired, #{}),
    Public = maps:without([runtime_config], Desired),
    DesiredFields = maps:merge(Runtime, Public),
    RevokedBefore = maps:get(revoked, Base, false),
    Revoked = case maps:find(revoked, Public) of
                  {ok, false} -> false;
                  {ok, true} -> true;
                  error -> RevokedBefore
              end,
    Merged = (maps:merge(Base, DesiredFields))#{revoked => Revoked},
    {ok, normalize_authorization_metadata(Merged, DesiredFields)};
next_config(enable, Base, _Desired) ->
    case maps:get(revoked, Base, false) of
        true -> {error, revoked};
        false -> {ok, Base#{enabled => true}}
    end;
next_config(disable, Base, _Desired) ->
    {ok, Base#{enabled => false}};
next_config(revoke, Base, Desired) ->
    Public = maps:without([runtime_config], Desired),
    Reason = maps:get(authorization_reason, Public, revoked),
    {ok, (maps:merge(Base, Public))#{enabled => false,
                                   authorized => false,
                                   authorization_reason => Reason,
                                   revoked => true}}.

persist_next_config(disable, PeerId, BaseConfig, Next) ->
    case dynamic_gateway_config(PeerId, BaseConfig) of
        {ok, GatewayConfig} ->
            persist_dynamic_pair_disable(PeerId, GatewayConfig, Next);
        not_dynamic_client ->
            put_single_config(disable, Next);
        {error, Reason} ->
            logger:warning(
              "Dynamic client disable could not quiesce companion gateway: ~p",
              [Reason]),
            put_single_config(disable, Next)
    end;
persist_next_config(enable, PeerId, BaseConfig, Next) ->
    case dynamic_gateway_config(PeerId, BaseConfig) of
        {ok, GatewayConfig} ->
            persist_dynamic_pair_enable(PeerId,
                                        BaseConfig,
                                        GatewayConfig,
                                        Next);
        not_dynamic_client ->
            put_single_config(enable, Next);
        {error, Reason} ->
            {error, Reason}
    end;
persist_next_config(revoke, PeerId, BaseConfig, Next) ->
    case dynamic_gateway_config(PeerId, BaseConfig) of
        {ok, GatewayConfig} ->
            persist_dynamic_pair_revoke(PeerId, GatewayConfig, Next);
        not_dynamic_client ->
            put_single_config(revoke, Next);
        {error, Reason} ->
            logger:warning(
              "Dynamic client revoke could not quiesce companion gateway: ~p",
              [Reason]),
            put_single_config(revoke, Next)
    end;
persist_next_config(Operation, _PeerId, _BaseConfig, Next) ->
    put_single_config(Operation, Next).

persist_dynamic_pair_disable(PeerId, GatewayConfig, Next) ->
    DeviceId = maps:get(device_id, Next),
    QuiescedGateway = GatewayConfig#{enabled => false},
    case vpn_peer_registry:put_many([QuiescedGateway, Next]) of
        {ok, SafeEntries} ->
            case vpn_dynamic_pair:await_stopped(DeviceId) of
                ok ->
                    pair_operation_result(disable, PeerId, SafeEntries);
                {error, _} = Error ->
                    Error
            end;
        {error, Reason} ->
            {error, Reason}
    end.

persist_dynamic_pair_revoke(PeerId, GatewayConfig, Next) ->
    DeviceId = maps:get(device_id, Next),
    QuiescedGateway = GatewayConfig#{enabled => false},
    case vpn_peer_registry:put_many([QuiescedGateway, Next]) of
        {ok, SafeEntries} ->
            case vpn_dynamic_pair:await_stopped(DeviceId) of
                ok ->
                    pair_operation_result(revoke, PeerId, SafeEntries);
                {error, _} = Error ->
                    Error
            end;
        {error, Reason} ->
            {error, Reason}
    end.

persist_dynamic_pair_enable(PeerId, BaseConfig, GatewayConfig, Next) ->
    DeviceId = maps:get(device_id, Next),
    EnabledGateway = GatewayConfig#{enabled => true},
    case vpn_peer_registry:put_many([EnabledGateway, Next]) of
        {ok, SafeEntries} ->
            case vpn_dynamic_pair:await_established(DeviceId) of
                ok ->
                    pair_operation_result(enable, PeerId, SafeEntries);
                {error, _} = Error ->
                    rollback_failed_pair_enable(DeviceId,
                                                BaseConfig,
                                                GatewayConfig),
                    Error
            end;
        {error, Reason} ->
            {error, Reason}
    end.

rollback_failed_pair_enable(DeviceId, BaseConfig, GatewayConfig) ->
    DisabledClient = BaseConfig#{enabled => false},
    DisabledGateway = GatewayConfig#{enabled => false},
    case vpn_peer_registry:put_many([DisabledGateway, DisabledClient]) of
        {ok, _} ->
            _ = vpn_dynamic_pair:await_stopped(DeviceId),
            ok;
        {error, Reason} ->
            logger:error("Dynamic pair enable rollback failed: ~p", [Reason]),
            ok
    end.

pair_operation_result(Operation, PeerId, SafeEntries) ->
    case safe_peer_entry(PeerId, SafeEntries) of
        {ok, Safe} ->
            {ok, #{operation => Operation, peer => Safe}};
        {error, _} = Error ->
            Error
    end.

put_single_config(Operation, Next) ->
    case vpn_peer_registry:put(Next) of
        {ok, Safe} -> {ok, #{operation => Operation, peer => Safe}};
        {error, Reason} -> {error, Reason}
    end.

dynamic_gateway_config(ClientId,
                       #{allocation_role := client,
                         allocation_id := AllocationId,
                         device_id := DeviceId,
                         remote_peer_id := GatewayId}) ->
    case vpn_peer_registry:config(GatewayId) of
        {ok, GatewayConfig} ->
            case maps:get(allocation_role, GatewayConfig, undefined) =:= gateway andalso
                 maps:get(allocation_id, GatewayConfig, undefined) =:= AllocationId andalso
                 maps:get(device_id, GatewayConfig, undefined) =:= DeviceId andalso
                 maps:get(remote_peer_id, GatewayConfig, undefined) =:= ClientId of
                true -> {ok, GatewayConfig};
                false -> {error, {dynamic_pair_gateway_mismatch, GatewayId}}
            end;
        {error, not_found} ->
            {error, {dynamic_pair_gateway_not_found, GatewayId}}
    end;
dynamic_gateway_config(_PeerId, _BaseConfig) ->
    not_dynamic_client.

safe_peer_entry(PeerId, SafeEntries) ->
    case [Entry || #{id := Id} = Entry <- SafeEntries, Id =:= PeerId] of
        [Safe] -> {ok, Safe};
        _ -> {error, dynamic_pair_client_result_missing}
    end.


normalize_authorization_metadata(Config, DesiredFields) ->
    AuthorizationChanged = maps:is_key(authorization_mode, DesiredFields) orelse
                           maps:is_key(authorized, DesiredFields),
    ReasonProvided = maps:is_key(authorization_reason, DesiredFields),
    case AuthorizationChanged andalso not ReasonProvided of
        true -> Config#{authorization_reason => undefined};
        false -> Config
    end.

validate_dynamic_command(DeviceId, Command)
  when is_binary(DeviceId), byte_size(DeviceId) > 0 ->
    case validate_command(Command) of
        {ok, #{operation := upsert, revision := Revision,
               desired_state := Desired} = Normalized}
          when Revision > 0 ->
            case maps:get(device_id, Desired, DeviceId) of
                DeviceId ->
                    {ok, Normalized#{desired_state => Desired#{device_id => DeviceId},
                                     dynamic_device_id => DeviceId}};
                _Other ->
                    {error, dynamic_peer_device_id_mismatch}
            end;
        {ok, #{operation := upsert, revision := 0}} ->
            {error, dynamic_pair_positive_revision_required};
        {ok, #{operation := _Other}} ->
            {error, dynamic_pair_upsert_required};
        {error, _} = Error ->
            Error
    end;
validate_dynamic_command(_DeviceId, _Command) ->
    {error, invalid_dynamic_pair_command}.

validate_command(Command) when is_map(Command) ->
    PeerId = maps:get(peer_id, Command, undefined),
    Revision = maps:get(revision, Command, undefined),
    Operation = maps:get(operation, Command, undefined),
    Source = maps:get(source, Command, undefined),
    Desired = maps:get(desired_state, Command, #{}),
    case {valid_peer_id(PeerId), is_integer(Revision) andalso Revision >= 0,
          lists:member(Operation, [upsert, enable, disable, revoke, remove]),
          valid_source(Source), is_map(Desired),
          validate_recovery_manifest(Desired)} of
        {true, true, true, true, true, ok} ->
            {ok, #{peer_id => PeerId,
                   revision => Revision,
                   operation => Operation,
                   source => Source,
                   desired_state => Desired}};
        {true, true, true, true, true, {error, Reason}} ->
            {error, Reason};
        _ -> {error, invalid_command}
    end;
validate_command(_) ->
    {error, invalid_command}.


validate_recovery_manifest(Desired) when is_map(Desired) ->
    case maps:get(recovery_manifest, Desired, undefined) of
        undefined -> ok;
        Manifest -> vpn_recovery_manifest:validate(Manifest)
    end;
validate_recovery_manifest(_Desired) ->
    {error, invalid_recovery_manifest}.

valid_peer_id(Value) when is_atom(Value) -> Value =/= undefined;
valid_peer_id(Value) when is_binary(Value) -> byte_size(Value) > 0;
valid_peer_id(_Value) -> false.

valid_source(Value) when is_atom(Value) -> Value =/= undefined;
valid_source(Value) when is_binary(Value) -> byte_size(Value) > 0;
valid_source(_Value) -> false.

restore_heads() ->
    case recovery_heads() of
        {ok, DurableHeads} ->
            {ok, maps:merge(bootstrap_heads(), DurableHeads)};
        {error, _} = Error ->
            Error
    end.

%% @doc Return only validated durable provisioning heads.
%%
%% This pure recovery boundary is intentionally callable before the
%% vpn_provisioning process starts. The peer registry uses it during startup so
%% runtime configuration is reconstructed before vpn_peer_sup starts children.
recovery_heads() ->
    case vpn_projection:get() of
        {ok, _ProjectionVersion, #{provisioning := Section}} ->
            case migrate_loaded_provisioning_section(Section) of
                {ok, Entries} ->
                    {ok,
                     maps:map(
                       fun(_PeerId, Entry) ->
                               Entry#{durable => true}
                       end,
                       Entries)};
                {error, _} = Error ->
                    Error
            end;
        {ok, _ProjectionVersion, _Projection} ->
            {error, invalid_projection_payload};
        {error, Reason} ->
            {error, {projection_unavailable, Reason}};
        Other ->
            {error, {invalid_projection_result, Other}}
    end.

bootstrap_heads() ->
    maps:from_list(
      [{maps:get(id, Entry), bootstrap_head_from_entry(Entry)}
       || Entry <- vpn_peer_registry:list()]).

bootstrap_head(PeerId) ->
    case vpn_peer_registry:get(PeerId) of
        {ok, Entry} -> bootstrap_head_from_entry(Entry);
        {error, not_found} ->
            #{revision => 0,
              digest => undefined,
              digest_version => vpn_provisioning_command_digest:schema_version(),
              phase => applied,
              operation => bootstrap,
              source => bootstrap_sys_config,
              lifecycle_state => active,
              desired_state => #{},
              updated_at => 0,
              durable => false}
    end.

bootstrap_head_from_entry(Entry) ->
    Base = #{revision => maps:get(revision, Entry, 0),
             digest => undefined,
             digest_version => vpn_provisioning_command_digest:schema_version(),
             phase => applied,
             operation => bootstrap,
             source => maps:get(provisioning_source,
                                Entry,
                                bootstrap_sys_config),
             lifecycle_state => lifecycle_from_safe_entry(Entry),
             desired_state => durable_desired_state(Entry),
             updated_at => maps:get(updated_at, Entry, 0),
             durable => false},
    case {maps:get(allocation_role, Entry, undefined),
          maps:get(device_id, Entry, undefined)} of
        {client, DeviceId} when is_binary(DeviceId), byte_size(DeviceId) > 0 ->
            Base#{dynamic_device_id => DeviceId};
        _ ->
            Base
    end.

lifecycle_from_safe_entry(#{revoked := true}) -> revoked;
lifecycle_from_safe_entry(#{enabled := false}) -> disabled;
lifecycle_from_safe_entry(_) -> active.



migrate_loaded_provisioning_section(Section) ->
    case normalize_provisioning_section(Section) of
        {ok, Entries0} ->
            {Entries, Changed} = migrate_loaded_provisioning_entries(Entries0),
            case Changed of
                false ->
                    {ok, Entries};
                true ->
                    persist_loaded_provisioning_migration(Entries0, Entries)
            end;
        {error, _} = Error ->
            Error
    end.

migrate_loaded_provisioning_entries(Entries0) ->
    maps:fold(
      fun(PeerId, Entry0, {Acc, Changed0}) ->
              case maps:get(digest_version, Entry0, 1) of
                  1 ->
                      Entry = migrate_loaded_provisioning_entry(PeerId, Entry0),
                      {Acc#{PeerId => Entry}, true};
                  _ ->
                      {Acc#{PeerId => Entry0}, Changed0}
              end
      end,
      {#{}, false},
      Entries0).

migrate_loaded_provisioning_entry(PeerId, Entry0) ->
    Command = #{peer_id => PeerId,
                revision => maps:get(revision, Entry0),
                operation => maps:get(operation, Entry0),
                source => maps:get(source, Entry0),
                desired_state =>
                    normalize_legacy_projection_desired_state(
                      maps:get(desired_state, Entry0))},
    Entry0#{digest => vpn_provisioning_command_digest:digest(Command),
            digest_version =>
                vpn_provisioning_command_digest:schema_version()}.

%% Legacy heads persisted registry projection defaults rather than the exact
%% IAS command desired_state. A non-revoked registry row always contributed
%% revoked => false, so it must be removed when reconstructing the command.
normalize_legacy_projection_desired_state(#{revoked := false} = Desired) ->
    maps:remove(revoked, Desired);
normalize_legacy_projection_desired_state(Desired) ->
    Desired.

persist_loaded_provisioning_migration(ExpectedEntries, MigratedEntries) ->
    Update =
        fun(Section0) ->
                case normalize_provisioning_section(Section0) of
                    {ok, ExpectedEntries} ->
                        {ok, #{schema_version => ?PROVISIONING_SCHEMA_VERSION,
                               entries => MigratedEntries}};
                    {ok, _OtherEntries} ->
                        {error, provisioning_projection_conflict};
                    {error, _} = Error ->
                        Error
                end
        end,
    case vpn_projection:update(provisioning, Update) of
        {ok, _Version, _Projection} ->
            {ok, MigratedEntries};
        {ok, unchanged, _Version, _Projection} ->
            {ok, MigratedEntries};
        {error, Reason} ->
            {error, {provisioning_digest_migration_failed, Reason}};
        Other ->
            {error, {invalid_provisioning_digest_migration_result, Other}}
    end.

normalize_provisioning_section(Section) when map_size(Section) =:= 0 ->
    {ok, #{}};
normalize_provisioning_section(#{schema_version := Version,
                                 entries := Entries} = Section)
  when (Version =:= 1 orelse Version =:= ?PROVISIONING_SCHEMA_VERSION),
       is_map(Entries), map_size(Section) =:= 2 ->
    validate_provisioning_entries(maps:to_list(Entries), #{}, Version);
normalize_provisioning_section(#{schema_version := Version}) ->
    {error, {unsupported_provisioning_schema_version, Version}};
normalize_provisioning_section(_Section) ->
    {error, invalid_provisioning_projection}.

validate_provisioning_entries([], Acc, _SectionVersion) ->
    {ok, Acc};
validate_provisioning_entries([{PeerId, Entry0} | Rest], Acc, SectionVersion) ->
    Entry = case SectionVersion of
                1 -> Entry0#{digest_version => 1};
                _ -> Entry0
            end,
    case valid_peer_id(PeerId) andalso valid_provisioning_entry(Entry) of
        true -> validate_provisioning_entries(Rest, Acc#{PeerId => Entry},
                                              SectionVersion);
        false -> {error, {invalid_provisioning_entry, PeerId}}
    end.

valid_provisioning_entry(Entry) when is_map(Entry) ->
    Allowed = [revision,
               digest,
               digest_version,
               phase,
               operation,
               source,
               lifecycle_state,
               desired_state,
               dynamic_device_id,
               updated_at],
    Unknown = maps:keys(maps:without(Allowed, Entry)),
    Revision = maps:get(revision, Entry, undefined),
    Digest = maps:get(digest, Entry, undefined),
    DigestVersion = maps:get(digest_version, Entry, undefined),
    Phase = maps:get(phase, Entry, undefined),
    Operation = maps:get(operation, Entry, undefined),
    Source = maps:get(source, Entry, undefined),
    Lifecycle = maps:get(lifecycle_state, Entry, undefined),
    Desired = maps:get(desired_state, Entry, undefined),
    UpdatedAt = maps:get(updated_at, Entry, undefined),
    DynamicDeviceId = maps:get(dynamic_device_id, Entry, undefined),
    Unknown =:= [] andalso
    is_integer(Revision) andalso Revision >= 0 andalso
    is_binary(Digest) andalso byte_size(Digest) =:= 32 andalso
    lists:member(DigestVersion, [1, vpn_provisioning_command_digest:schema_version()]) andalso
    lists:member(Phase, [pending, applied]) andalso
    lists:member(Operation, [upsert, enable, disable, revoke, remove]) andalso
    valid_source(Source) andalso
    lists:member(Lifecycle, [active, disabled, revoked, removed]) andalso
    is_map(Desired) andalso
    validate_recovery_manifest(Desired) =:= ok andalso
    is_integer(UpdatedAt) andalso UpdatedAt >= 0 andalso
    (DynamicDeviceId =:= undefined orelse
     (is_binary(DynamicDeviceId) andalso byte_size(DynamicDeviceId) > 0));
valid_provisioning_entry(_Entry) ->
    false.

persist_command_phase(Command, Digest, Phase, PreviousHead, State) ->
    PeerId = maps:get(peer_id, Command),
    Entry = ledger_entry(Command, Digest, Phase, PreviousHead),
    Expected = persistent_head(PreviousHead),
    Update = fun(Section0) ->
                     case normalize_provisioning_section(Section0) of
                         {ok, Entries0} ->
                             case maps:get(PeerId, Entries0, undefined) of
                                 Expected ->
                                     {ok, #{schema_version => ?PROVISIONING_SCHEMA_VERSION,
                                            entries => Entries0#{PeerId => Entry}}};
                                 _ ->
                                     {error, provisioning_projection_conflict}
                             end;
                         {error, _} = Error -> Error
                     end
             end,
    case vpn_projection:update(provisioning, Update) of
        {ok, _Version, _Projection} ->
            {ok, put_head(PeerId, Entry#{durable => true}, State)};
        {ok, unchanged, _Version, _Projection} ->
            {ok, put_head(PeerId, Entry#{durable => true}, State)};
        {error, Reason} ->
            {error, {provisioning_ledger_commit_failed, Reason}};
        Other ->
            {error, {invalid_provisioning_ledger_result, Other}}
    end.

migrate_legacy_head(Command, Digest, Head, State) ->
    PeerId = maps:get(peer_id, Command),
    Migrated = (maps:remove(durable, Head))#{digest => Digest,
                                             digest_version =>
                                                 vpn_provisioning_command_digest:schema_version()},
    Expected = maps:remove(durable, Head),
    Update = fun(Section0) ->
                     case normalize_provisioning_section(Section0) of
                         {ok, Entries0} ->
                             case maps:get(PeerId, Entries0, undefined) of
                                 Expected ->
                                     {ok, #{schema_version => ?PROVISIONING_SCHEMA_VERSION,
                                            entries => Entries0#{PeerId => Migrated}}};
                                 _ ->
                                     {error, provisioning_projection_conflict}
                             end;
                         {error, _} = Error -> Error
                     end
             end,
    case vpn_projection:update(provisioning, Update) of
        {ok, _Version, _Projection} ->
            Durable = Migrated#{durable => true},
            {ok, put_head(PeerId, Durable, State), Durable};
        {ok, unchanged, _Version, _Projection} ->
            Durable = Migrated#{durable => true},
            {ok, put_head(PeerId, Durable, State), Durable};
        {error, Reason} ->
            {error, {provisioning_digest_migration_failed, Reason}};
        Other ->
            {error, {invalid_provisioning_digest_migration_result, Other}}
    end.

persistent_head(#{durable := true} = Head) ->
    maps:remove(durable, Head);
persistent_head(_Head) ->
    undefined.

put_head(PeerId, Head, State) ->
    Heads = maps:get(heads, State),
    State#{heads => Heads#{PeerId => Head}}.

ledger_entry(#{revision := Revision}, Digest, applied,
             #{revision := Revision,
               digest := Digest,
               phase := pending} = Pending) ->
    (maps:remove(durable, Pending))#{phase => applied,
                                     updated_at => erlang:system_time(millisecond)};
ledger_entry(Command, Digest, pending, PreviousHead) ->
    Operation = maps:get(operation, Command),
    PreviousDesired = maps:get(desired_state, PreviousHead, #{}),
    SafeDesired = durable_desired_state(maps:get(desired_state, Command, #{})),
    ProjectedDesired = project_desired_state(Operation,
                                             PreviousDesired,
                                             SafeDesired),
    Base = #{revision => maps:get(revision, Command),
             digest => Digest,
             digest_version => vpn_provisioning_command_digest:schema_version(),
             phase => pending,
             operation => Operation,
             source => maps:get(source, Command),
             lifecycle_state => lifecycle_state(Operation, ProjectedDesired),
             desired_state => ProjectedDesired,
             updated_at => erlang:system_time(millisecond)},
    DynamicDeviceId = maps:get(dynamic_device_id,
                               Command,
                               maps:get(dynamic_device_id,
                                        PreviousHead,
                                        undefined)),
    case DynamicDeviceId of
        undefined -> Base;
        DeviceId -> Base#{dynamic_device_id => DeviceId}
    end.

project_desired_state(upsert, Previous, Desired) ->
    Merged0 = maps:merge(Previous, Desired),
    Revoked = case maps:find(revoked, Desired) of
                  {ok, Value} -> Value;
                  error -> maps:get(revoked, Previous, false)
              end,
    normalize_authorization_metadata(Merged0#{revoked => Revoked}, Desired);
project_desired_state(enable, Previous, _Desired) ->
    Previous#{enabled => true};
project_desired_state(disable, Previous, _Desired) ->
    Previous#{enabled => false};
project_desired_state(revoke, Previous, Desired) ->
    Reason = maps:get(authorization_reason, Desired, revoked),
    (maps:merge(Previous, Desired))#{enabled => false,
                                     authorized => false,
                                     authorization_reason => Reason,
                                     revoked => true};
project_desired_state(remove, Previous, _Desired) ->
    Previous#{enabled => false}.

lifecycle_state(remove, _Desired) -> removed;
lifecycle_state(revoke, _Desired) -> revoked;
lifecycle_state(enable, _Desired) -> active;
lifecycle_state(disable, _Desired) -> disabled;
lifecycle_state(upsert, #{revoked := true}) -> revoked;
lifecycle_state(upsert, #{enabled := false}) -> disabled;
lifecycle_state(upsert, _Desired) -> active.

durable_desired_state(Desired) when is_map(Desired) ->
    maps:with([device_id,
               profile_id,
               authorization_mode,
               authorized,
               authorization_reason,
               certificate_fingerprint,
               enabled,
               revoked,
               allocation_id,
               allocator_instance_id,
               allocation_slot,
               allocation_generation,
               allocation_role,
               remote_peer_id,
               recovery_manifest],
              Desired);
durable_desired_state(_Desired) ->
    #{}.


%% ------------------------------------------------------------------
%% Stage 7B orphan decommission boundary
%% ------------------------------------------------------------------

normalize_orphan_decommission_request(Request) when is_map(Request) ->
    Allowed = [device_id,
               expected_heads,
               expected_peer_ids,
               expected_source,
               expected_allocation_id,
               remove_identity],
    Unknown = maps:keys(maps:without(Allowed, Request)),
    DeviceId = maps:get(device_id, Request, undefined),
    ExpectedHeads0 = maps:get(expected_heads, Request, undefined),
    ExpectedPeerIds0 = maps:get(expected_peer_ids, Request, undefined),
    ExpectedSource0 = maps:get(expected_source, Request, undefined),
    ExpectedAllocationId = maps:get(expected_allocation_id,
                                    Request,
                                    undefined),
    RemoveIdentity = maps:get(remove_identity, Request, false),
    case {Unknown,
          valid_orphan_device_id(DeviceId),
          normalize_ias_source(ExpectedSource0),
          normalize_expected_orphan_heads(ExpectedHeads0),
          normalize_expected_peer_ids(ExpectedPeerIds0),
          valid_optional_allocation_id(ExpectedAllocationId),
          is_boolean(RemoveIdentity)} of
        {[], true, {ok, ias}, {ok, ExpectedHeads}, {ok, ExpectedPeerIds},
         true, true} ->
            HeadPeerIds = [maps:get(peer_id, Head) || Head <- ExpectedHeads],
            case lists:all(fun(PeerId) -> lists:member(PeerId, ExpectedPeerIds) end,
                           HeadPeerIds) of
                true ->
                    {ok, #{device_id => DeviceId,
                           expected_heads => ExpectedHeads,
                           expected_peer_ids => ExpectedPeerIds,
                           expected_source => ias,
                           expected_allocation_id => ExpectedAllocationId,
                           remove_identity => RemoveIdentity}};
                false ->
                    {error, orphan_snapshot_peer_set_mismatch}
            end;
        {[_ | _], _, _, _, _, _, _} ->
            {error, {unknown_orphan_decommission_fields, Unknown}};
        _ ->
            {error, invalid_orphan_decommission_request}
    end;
normalize_orphan_decommission_request(_Request) ->
    {error, invalid_orphan_decommission_request}.

normalize_expected_orphan_heads(Heads) when is_list(Heads) ->
    normalize_expected_orphan_heads(Heads, []);
normalize_expected_orphan_heads(_Heads) ->
    {error, invalid_expected_orphan_heads}.

normalize_expected_orphan_heads([], Acc) ->
    Normalized = sort_orphan_heads(Acc),
    PeerIds = [maps:get(peer_id, Head) || Head <- Normalized],
    case length(PeerIds) =:= length(lists:usort(PeerIds)) of
        true -> {ok, Normalized};
        false -> {error, duplicate_expected_orphan_head}
    end;
normalize_expected_orphan_heads([Head | Rest], Acc) when is_map(Head) ->
    case normalize_expected_orphan_head(Head) of
        {ok, Normalized} ->
            normalize_expected_orphan_heads(Rest, [Normalized | Acc]);
        {error, _} = Error -> Error
    end;
normalize_expected_orphan_heads([_Invalid | _Rest], _Acc) ->
    {error, invalid_expected_orphan_head}.

normalize_expected_orphan_head(Head) ->
    PeerId = maps:get(peer_id, Head, undefined),
    Revision = maps:get(revision, Head, undefined),
    Digest = maps:get(digest, Head, undefined),
    Phase = maps:get(phase, Head, undefined),
    Source0 = maps:get(source, Head, undefined),
    case valid_orphan_peer_id(PeerId) andalso
         is_integer(Revision) andalso Revision >= 0 andalso
         is_binary(Digest) andalso byte_size(Digest) =:= 32 andalso
         lists:member(Phase, [pending, applied]) of
        false -> {error, invalid_expected_orphan_head};
        true ->
            case normalize_ias_source(Source0) of
                {ok, ias} ->
                    {ok, #{peer_id => PeerId,
                           revision => Revision,
                           digest => Digest,
                           phase => Phase,
                           source => ias}};
                error -> {error, invalid_expected_orphan_source}
            end
    end.

normalize_expected_peer_ids(PeerIds) when is_list(PeerIds) ->
    case lists:all(fun valid_orphan_peer_id/1, PeerIds) of
        true -> {ok, sort_terms(lists:usort(PeerIds))};
        false -> {error, invalid_expected_orphan_peer_ids}
    end;
normalize_expected_peer_ids(_PeerIds) ->
    {error, invalid_expected_orphan_peer_ids}.

normalize_ias_source(ias) -> {ok, ias};
normalize_ias_source(<<"ias">>) -> {ok, ias};
normalize_ias_source("ias") -> {ok, ias};
normalize_ias_source(_) -> error.

valid_orphan_device_id(Value) when is_binary(Value) -> byte_size(Value) > 0;
valid_orphan_device_id(_) -> false.

valid_orphan_peer_id(Value) when is_atom(Value) -> Value =/= undefined;
valid_orphan_peer_id(Value) when is_binary(Value) -> byte_size(Value) > 0;
valid_orphan_peer_id(_) -> false.

valid_optional_allocation_id(undefined) -> true;
valid_optional_allocation_id(Value) when is_binary(Value) -> byte_size(Value) > 0;
valid_optional_allocation_id(_) -> false.

decommission_orphan_validated(Request, State0) ->
    DeviceId = maps:get(device_id, Request),
    case current_orphan_snapshot(DeviceId, State0) of
        {error, Reason} ->
            {{error, Reason}, State0};
        {ok, Snapshot} ->
            case compare_orphan_snapshot(Request, Snapshot) of
                already_absent ->
                    {{ok, #{outcome => already_absent,
                            device_id => DeviceId,
                            completed_at => erlang:system_time(second)}},
                     State0};
                ok ->
                    execute_orphan_decommission(Request, Snapshot, State0);
                {error, Reason} ->
                    {{error, Reason}, State0}
            end
    end.

current_orphan_snapshot(DeviceId, State) ->
    Heads0 = [{PeerId, Head}
              || {PeerId, Head} <- maps:to_list(maps:get(heads, State)),
                 maps:get(durable, Head, false) =:= true,
                 orphan_head_device_id(Head) =:= DeviceId],
    case lists:all(fun({_PeerId, Head}) ->
                           normalize_ias_source(maps:get(source,
                                                         Head,
                                                         undefined)) =:=
                               {ok, ias}
                   end,
                   Heads0) of
        false -> {error, orphan_state_not_owned_by_ias};
        true ->
            case current_orphan_registry(DeviceId) of
                {ok, RegistryEntries} ->
                    case current_orphan_allocation(DeviceId) of
                        {error, Reason} ->
                            {error, {orphan_allocator_read_failed, Reason}};
                        Allocation ->
                            {ok, #{heads => Heads0,
                                   head_summaries => sort_orphan_heads(
                                                       [orphan_head_summary(PeerId, Head)
                                                        || {PeerId, Head} <- Heads0]),
                                   registry => RegistryEntries,
                                   registry_peer_ids => sort_terms(
                                                          [maps:get(id, Entry)
                                                           || Entry <- RegistryEntries]),
                                   allocation => Allocation}}
                    end;
                {error, _} = Error -> Error
            end
    end.

current_orphan_registry(DeviceId) ->
    case whereis(vpn_peer_registry) of
        undefined -> {error, vpn_peer_registry_unavailable};
        _Pid ->
            Entries = [Entry || Entry <- vpn_peer_registry:list(),
                                maps:get(device_id, Entry, undefined) =:= DeviceId],
            case lists:all(fun(Entry) ->
                                   normalize_ias_source(
                                     maps:get(provisioning_source,
                                              Entry,
                                              undefined)) =:= {ok, ias}
                           end,
                           Entries) of
                true -> {ok, Entries};
                false -> {error, orphan_registry_not_owned_by_ias}
            end
    end.

current_orphan_allocation(DeviceId) ->
    case whereis(vpn_peer_allocator) of
        undefined -> none;
        _Pid ->
            case vpn_peer_allocator:lookup(DeviceId) of
                {ok, Allocation} -> {active, Allocation};
                {error, not_found} ->
                    case vpn_peer_allocator:released(DeviceId) of
                        {ok, Released} -> {released, Released};
                        {error, not_found} -> none;
                        {error, Reason} -> {error, Reason}
                    end;
                {error, Reason} -> {error, Reason}
            end
    end.

orphan_head_device_id(Head) ->
    Desired = maps:get(desired_state, Head, #{}),
    case maps:get(dynamic_device_id, Head, undefined) of
        undefined -> maps:get(device_id, Desired, undefined);
        DeviceId -> DeviceId
    end.

orphan_head_summary(PeerId, Head) ->
    #{peer_id => PeerId,
      revision => maps:get(revision, Head, undefined),
      digest => maps:get(digest, Head, undefined),
      phase => maps:get(phase, Head, applied),
      source => ias}.

compare_orphan_snapshot(Request, Snapshot) ->
    ExpectedHeads = maps:get(expected_heads, Request),
    CurrentHeads = maps:get(head_summaries, Snapshot),
    ExpectedPeerIds = maps:get(expected_peer_ids, Request),
    CurrentRegistryIds = maps:get(registry_peer_ids, Snapshot),
    Allocation = maps:get(allocation, Snapshot),
    CurrentStatePresent = CurrentHeads =/= [] orelse
        CurrentRegistryIds =/= [] orelse allocation_active(Allocation),
    case CurrentStatePresent of
        false -> already_absent;
        true ->
            case CurrentHeads =:= ExpectedHeads of
                false -> {error, orphan_snapshot_conflict};
                true ->
                    case lists:all(fun(PeerId) ->
                                           lists:member(PeerId, ExpectedPeerIds)
                                   end,
                                   CurrentRegistryIds) andalso
                         allocation_matches_snapshot(
                           maps:get(expected_allocation_id, Request),
                           Allocation,
                           ExpectedPeerIds) of
                        true -> ok;
                        false -> {error, orphan_snapshot_conflict}
                    end
            end
    end.

allocation_active({active, _Allocation}) -> true;
allocation_active(_) -> false.

allocation_matches_snapshot(undefined, none, _ExpectedPeerIds) -> true;
allocation_matches_snapshot(undefined, {error, _Reason}, _ExpectedPeerIds) -> false;
allocation_matches_snapshot(undefined, {_State, _Allocation}, _ExpectedPeerIds) ->
    false;
allocation_matches_snapshot(ExpectedAllocationId, {State, Allocation}, ExpectedPeerIds)
  when State =:= active; State =:= released ->
    AllocationId = maps:get(allocation_id, Allocation, undefined),
    AllocationPeers = [maps:get(client_peer_id, Allocation, undefined),
                       maps:get(gateway_peer_id, Allocation, undefined)],
    AllocationId =:= ExpectedAllocationId andalso
    lists:all(fun(PeerId) -> lists:member(PeerId, ExpectedPeerIds) end,
              AllocationPeers);
allocation_matches_snapshot(_ExpectedAllocationId, _Allocation, _ExpectedPeerIds) ->
    false.

execute_orphan_decommission(Request, Snapshot, State0) ->
    PeerIds = decommission_peer_ids(Request, Snapshot),
    case remove_orphan_registry(maps:get(device_id, Request), PeerIds) of
        ok ->
            case release_orphan_allocation(Request, maps:get(allocation, Snapshot)) of
                {ok, AllocationResult, IdentityState} ->
                    case remove_orphan_heads(maps:get(heads, Snapshot), State0) of
                        {ok, State1} ->
                            {{ok, #{outcome => decommissioned,
                                    device_id => maps:get(device_id, Request),
                                    removed_peer_ids => PeerIds,
                                    removed_head_ids =>
                                        [PeerId || {PeerId, _Head} <-
                                                       maps:get(heads, Snapshot)],
                                    allocation => AllocationResult,
                                    identity_state => IdentityState,
                                    completed_at => erlang:system_time(second)}},
                             State1};
                        {error, Reason} -> {{error, Reason}, State0}
                    end;
                {error, Reason} -> {{error, Reason}, State0}
            end;
        {error, Reason} -> {{error, Reason}, State0}
    end.

decommission_peer_ids(Request, Snapshot) ->
    HeadIds = [PeerId || {PeerId, _Head} <- maps:get(heads, Snapshot)],
    RegistryIds = maps:get(registry_peer_ids, Snapshot),
    AllocationIds = case maps:get(allocation, Snapshot) of
                        {_State, Allocation} when is_map(Allocation) ->
                            [maps:get(client_peer_id, Allocation, undefined),
                             maps:get(gateway_peer_id, Allocation, undefined)];
                        _ -> []
                    end,
    sort_terms(lists:usort([PeerId
                            || PeerId <- maps:get(expected_peer_ids, Request) ++
                                         HeadIds ++ RegistryIds ++ AllocationIds,
                               valid_orphan_peer_id(PeerId)])).

remove_orphan_registry(_DeviceId, []) -> ok;
remove_orphan_registry(DeviceId, PeerIds) ->
    case whereis(vpn_peer_registry) of
        undefined -> {error, vpn_peer_registry_unavailable};
        _Pid ->
            case vpn_peer_registry:remove_many_if_owned(DeviceId,
                                                         PeerIds,
                                                         ias) of
                ok -> reconcile_orphan_runtime(PeerIds);
                {error, Reason} ->
                    {error, {orphan_registry_removal_failed, Reason}}
            end
    end.

reconcile_orphan_runtime(PeerIds) ->
    Result = case whereis(vpn_peer_reconciler) of
                 undefined ->
                     lists:foldl(
                       fun(PeerId, Acc) ->
                               case vpn_manager:peer_running(PeerId) of
                                   true ->
                                       case vpn_manager:stop_peer(PeerId) of
                                           ok -> Acc;
                                           {error, not_found} -> Acc;
                                           {error, Reason} -> [{PeerId, Reason} | Acc]
                                       end;
                                   false -> Acc
                               end
                       end,
                       [],
                       PeerIds);
                 _Pid ->
                     case vpn_peer_reconciler:reconcile_now() of
                         #{failed := Failed} -> Failed;
                         {error, Reason} -> [{runtime_reconcile, Reason}];
                         _ -> []
                     end
             end,
    case Result of
        [] -> ok;
        _ -> {error, {orphan_runtime_removal_failed, Result}}
    end.

release_orphan_allocation(_Request, none) ->
    {ok, none, not_applicable};
release_orphan_allocation(_Request, {error, Reason}) ->
    {error, {orphan_allocator_read_failed, Reason}};
release_orphan_allocation(Request, {_State, _Allocation}) ->
    DeviceId = maps:get(device_id, Request),
    ExpectedAllocationId = maps:get(expected_allocation_id, Request),
    case vpn_peer_allocator:release_if(DeviceId, ExpectedAllocationId) of
        {ok, Released} -> finish_orphan_allocation(Request, Released);
        {error, allocation_snapshot_conflict} ->
            {error, orphan_snapshot_conflict};
        {error, Reason} -> {error, {orphan_allocation_release_failed, Reason}}
    end.

finish_orphan_allocation(Request, Allocation) ->
    case maybe_release_orphan_identity(maps:get(remove_identity, Request),
                                       Allocation) of
        {ok, IdentityState} ->
            {ok, maps:with([allocation_id,
                            allocator_instance_id,
                            slot,
                            generation,
                            client_peer_id,
                            gateway_peer_id,
                            state,
                            released_at],
                           Allocation),
             IdentityState};
        {error, Reason} ->
            {error, {orphan_identity_release_failed, Reason}}
    end.

maybe_release_orphan_identity(false, _Allocation) -> {ok, retained};
maybe_release_orphan_identity(true, Allocation) ->
    AllocationId = maps:get(allocation_id, Allocation, undefined),
    Provider = application:get_env(vpn,
                                   dynamic_identity_factory_module,
                                   vpn_dynamic_identity_factory),
    try Provider:release(AllocationId) of
        {ok, _SafeResult} -> {ok, removed};
        {error, dynamic_identity_not_found} -> {ok, absent};
        {error, not_found} -> {ok, absent};
        {error, Reason} -> {error, Reason};
        Other -> {error, {invalid_dynamic_identity_release_result, Other}}
    catch
        error:undef -> {error, {dynamic_identity_release_unsupported, Provider}};
        Class:Reason ->
            {error, {dynamic_identity_release_failed, Provider, Class, Reason}}
    end.

remove_orphan_heads([], State) -> {ok, State};
remove_orphan_heads(Heads, State) ->
    Expected = maps:from_list(
                 [{PeerId, maps:remove(durable, Head)}
                  || {PeerId, Head} <- Heads]),
    PeerIds = maps:keys(Expected),
    Update = fun(Section0) ->
                     case normalize_provisioning_section(Section0) of
                         {ok, Entries0} ->
                             case lists:all(
                                    fun(PeerId) ->
                                            maps:get(PeerId,
                                                     Entries0,
                                                     undefined) =:=
                                                maps:get(PeerId, Expected)
                                    end,
                                    PeerIds) of
                                 true ->
                                     {ok, #{schema_version => ?PROVISIONING_SCHEMA_VERSION,
                                            entries =>
                                                lists:foldl(fun maps:remove/2,
                                                            Entries0,
                                                            PeerIds)}};
                                 false ->
                                     {error, orphan_snapshot_conflict}
                             end;
                         {error, _} = Error -> Error
                     end
             end,
    case vpn_projection:update(provisioning, Update) of
        {ok, _Version, _Projection} ->
            {ok, remove_heads_from_state(PeerIds, State)};
        {ok, unchanged, _Version, _Projection} ->
            {ok, remove_heads_from_state(PeerIds, State)};
        {error, Reason} -> {error, {orphan_head_removal_failed, Reason}};
        Other -> {error, {invalid_orphan_head_removal_result, Other}}
    end.

remove_heads_from_state(PeerIds, State) ->
    Heads0 = maps:get(heads, State),
    Heads = lists:foldl(fun maps:remove/2, Heads0, PeerIds),
    State#{heads => Heads}.

sort_orphan_heads(Heads) ->
    lists:sort(fun(A, B) ->
                       term_to_binary(maps:get(peer_id, A)) =<
                           term_to_binary(maps:get(peer_id, B))
               end,
               Heads).

sort_terms(Terms) ->
    lists:sort(fun(A, B) -> term_to_binary(A) =< term_to_binary(B) end,
               Terms).

provisioning_status(State) ->
    Heads = maps:get(heads, State),
    DurableHeads = length([ok || {_PeerId, Head} <- maps:to_list(Heads),
                                  maps:get(durable, Head, false)]),
    Pending = length([ok || {_PeerId, Head} <- maps:to_list(Heads),
                             maps:get(phase, Head, applied) =:= pending]),
    (maps:without([heads, history], State))#{persistence => durable,
                                             durable_heads => DurableHeads,
                                             pending_commands => Pending}.

command_digest(Command) ->
    vpn_provisioning_command_digest:digest(Command).

legacy_command_digest(Command) ->
    vpn_provisioning_command_digest:legacy_digest(Command).

command_summary(Command) when is_map(Command) ->
    maps:with([peer_id, revision, operation, source], Command);
command_summary(_) -> undefined.

record_applied(Command, Result, State0) ->
    State1 = add_history(Command, Result, State0),
    Revocations = maps:get(revocations, State1) +
        case maps:get(operation, Command) of revoke -> 1; _ -> 0 end,
    State1#{commands_applied => maps:get(commands_applied, State1) + 1,
            revocations => Revocations,
            last_command => command_summary(Command),
            last_result => Result}.

record_unchanged(Command, Result, State0) ->
    State1 = add_history(Command, Result, State0),
    State1#{commands_unchanged => maps:get(commands_unchanged, State1) + 1,
            last_command => command_summary(Command), last_result => Result}.

record_stale(Command, Result, State0) ->
    State1 = add_history(Command, Result, State0),
    State1#{commands_rejected => maps:get(commands_rejected, State1) + 1,
            stale_revisions => maps:get(stale_revisions, State1) + 1,
            last_command => command_summary(Command), last_result => Result}.

record_rejected(Command, Result, State0) ->
    State = maybe_add_history(Command, Result, State0),
    State#{commands_rejected => maps:get(commands_rejected, State) + 1,
           last_command => command_summary(Command), last_result => Result}.

maybe_add_history(Command, Result, State) when is_map(Command) ->
    case maps:is_key(peer_id, Command) andalso
         maps:is_key(revision, Command) andalso
         maps:is_key(operation, Command) andalso
         maps:is_key(source, Command) of
        true -> add_history(Command, Result, State);
        false -> State
    end;
maybe_add_history(_Command, _Result, State) ->
    State.

add_history(Command, Result, State) ->
    PeerId = maps:get(peer_id, Command),
    Histories = maps:get(history, State),
    Existing = maps:get(PeerId, Histories, []),
    Entry = (command_summary(Command))#{result => Result,
                                      recorded_at => erlang:system_time(second)},
    Updated = lists:sublist([Entry | Existing], ?HISTORY_LIMIT),
    State#{history => Histories#{PeerId => Updated}}.
