%%%-------------------------------------------------------------------
%% @doc Durable reservation allocator for dynamic VPN peer pairs.
%%
%% The allocator owns transport resource selection. IAS supplies only a stable
%% Device identifier. Reservations are idempotent per Device and are committed
%% to the durable VPN projection before becoming visible in memory or through
%% the public API. Binary peer identifiers avoid dynamic atom creation.
%%
%% This stage persists allocator identity, the monotonic generation barrier and
%% active allocations. It still does not create certificates, runtime
%% configurations, or peer processes.
%%%-------------------------------------------------------------------
-module(vpn_peer_allocator).

-behaviour(gen_server).

-export([start_link/0,
         ensure/1,
         lookup/1,
         released/1,
         release/1,
         list/0,
         status/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(ALLOCATOR_SCHEMA_VERSION, 1).

-type device_id() :: binary().
-type allocation() :: map().

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec ensure(device_id()) -> {ok, allocation()} | {error, term()}.
ensure(DeviceId) when is_binary(DeviceId), byte_size(DeviceId) > 0 ->
    gen_server:call(?SERVER, {ensure, DeviceId});
ensure(_DeviceId) ->
    {error, invalid_device_id}.

-spec lookup(device_id()) -> {ok, allocation()} | {error, term()}.
lookup(DeviceId) when is_binary(DeviceId), byte_size(DeviceId) > 0 ->
    gen_server:call(?SERVER, {lookup, DeviceId});
lookup(_DeviceId) ->
    {error, invalid_device_id}.

-spec released(device_id()) -> {ok, allocation()} | {error, term()}.
released(DeviceId) when is_binary(DeviceId), byte_size(DeviceId) > 0 ->
    gen_server:call(?SERVER, {released, DeviceId});
released(_DeviceId) ->
    {error, invalid_device_id}.

-spec release(device_id()) -> {ok, allocation()} | {error, term()}.
release(DeviceId) when is_binary(DeviceId), byte_size(DeviceId) > 0 ->
    gen_server:call(?SERVER, {release, DeviceId});
release(_DeviceId) ->
    {error, invalid_device_id}.

-spec list() -> [allocation()].
list() ->
    gen_server:call(?SERVER, list).

-spec status() -> map().
status() ->
    gen_server:call(?SERVER, status).

init([]) ->
    case load_config() of
        {ok, Config} ->
            case load_or_initialize_projection(Config) of
                {ok, AllocatorSection, BySlot} ->
                    {ok, state_from_projection(Config,
                                               AllocatorSection,
                                               BySlot)};
                {error, Reason} ->
                    {stop, {allocator_projection_load_failed, Reason}}
            end;
        {error, Reason} ->
            {stop, {invalid_dynamic_peer_allocator_config, Reason}}
    end.

handle_call({ensure, DeviceId}, _From,
            State = #{by_device := ByDevice}) ->
    case maps:find(DeviceId, ByDevice) of
        {ok, Allocation} ->
            {reply, {ok, Allocation}, State};
        error ->
            reserve(DeviceId, State)
    end;
handle_call({lookup, DeviceId}, _From,
            State = #{by_device := ByDevice}) ->
    Reply = case maps:find(DeviceId, ByDevice) of
                {ok, Allocation} -> {ok, Allocation};
                error -> {error, not_found}
            end,
    {reply, Reply, State};
handle_call({released, DeviceId}, _From,
            State = #{released_by_device := ReleasedByDevice}) ->
    Reply = case maps:find(DeviceId, ReleasedByDevice) of
                {ok, Allocation} -> {ok, Allocation};
                error -> {error, not_found}
            end,
    {reply, Reply, State};
handle_call({release, DeviceId}, _From,
            State = #{by_device := ByDevice,
                      by_slot := BySlot,
                      released_by_device := ReleasedByDevice}) ->
    case maps:take(DeviceId, ByDevice) of
        {Allocation, RemainingByDevice} ->
            Slot = maps:get(slot, Allocation),
            RemainingBySlot = maps:remove(Slot, BySlot),
            Released = Allocation#{state => released,
                                     released_at =>
                                         erlang:system_time(second)},
            NewReleasedByDevice = ReleasedByDevice#{DeviceId => Released},
            NewSection = allocator_section(State,
                                           RemainingByDevice,
                                           NewReleasedByDevice,
                                           maps:get(next_generation, State)),
            case commit_allocator_section(NewSection, State) of
                {ok, CommittedState} ->
                    {reply, {ok, Released},
                     CommittedState#{by_slot => RemainingBySlot}};
                {error, Reason} ->
                    {reply, {error, {allocator_persistence_failed, Reason}},
                     State}
            end;
        error ->
            case maps:find(DeviceId, ReleasedByDevice) of
                {ok, Released} -> {reply, {ok, Released}, State};
                error -> {reply, {error, not_found}, State}
            end
    end;
handle_call(list, _From, State = #{by_device := ByDevice}) ->
    Allocations = maps:values(ByDevice),
    Sorted = lists:sort(fun compare_allocations/2, Allocations),
    {reply, Sorted, State};
handle_call(status, _From,
            State = #{config := Config, by_device := ByDevice}) ->
    Capacity = maps:get(capacity, Config),
    Allocated = map_size(ByDevice),
    {reply, #{persistence => durable,
              capacity => Capacity,
              allocated => Allocated,
              free => Capacity - Allocated},
     State};
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_operation}, State}.

handle_cast(_Message, State) ->
    {noreply, State}.

handle_info(_Message, State) ->
    {noreply, State}.

reserve(DeviceId,
        State = #{config := Config,
                  allocator_instance_id := AllocatorInstanceId,
                  next_generation := Generation,
                  by_device := ByDevice,
                  by_slot := BySlot,
                  released_by_device := ReleasedByDevice}) ->
    Capacity = maps:get(capacity, Config),
    case first_free_slot(1, Capacity, BySlot) of
        {ok, Slot} ->
            Allocation = build_allocation(DeviceId,
                                          Slot,
                                          AllocatorInstanceId,
                                          Generation,
                                          erlang:system_time(second),
                                          Config),
            NewByDevice = ByDevice#{DeviceId => Allocation},
            NewReleasedByDevice = maps:remove(DeviceId, ReleasedByDevice),
            NewNextGeneration = Generation + 1,
            NewSection = allocator_section(State,
                                           NewByDevice,
                                           NewReleasedByDevice,
                                           NewNextGeneration),
            case commit_allocator_section(NewSection, State) of
                {ok, CommittedState} ->
                    {reply, {ok, Allocation},
                     CommittedState#{by_slot => BySlot#{Slot => DeviceId}}};
                {error, Reason} ->
                    {reply, {error, {allocator_persistence_failed, Reason}},
                     State}
            end;
        {error, exhausted} = Error ->
            {reply, Error, State}
    end.

load_or_initialize_projection(Config) ->
    case safe_projection_get() of
        {ok, _ProjectionVersion,
         #{allocator := AllocatorSection}} when map_size(AllocatorSection) =:= 0 ->
            initialize_projection(Config);
        {ok, _ProjectionVersion,
         #{allocator := AllocatorSection}} ->
            validate_allocator_section(AllocatorSection, Config);
        {ok, _ProjectionVersion, _Projection} ->
            {error, invalid_projection_payload};
        {error, Reason} ->
            {error, Reason}
    end.

initialize_projection(Config) ->
    AllocatorSection = #{schema_version => ?ALLOCATOR_SCHEMA_VERSION,
                         allocator_instance_id => new_allocator_instance_id(),
                         next_generation => 1,
                         by_device => #{},
                         released_by_device => #{}},
    case safe_projection_update(
           fun(Current) when map_size(Current) =:= 0 ->
                   AllocatorSection;
              (_Current) ->
                   {error, allocator_projection_already_initialized}
           end) of
        {ok, _Version, Projection} ->
            validate_allocator_section(maps:get(allocator, Projection), Config);
        {ok, unchanged, _Version, Projection} ->
            validate_allocator_section(maps:get(allocator, Projection), Config);
        {error, Reason} ->
            {error, Reason}
    end.

validate_allocator_section(#{schema_version := ?ALLOCATOR_SCHEMA_VERSION,
                             allocator_instance_id := AllocatorInstanceId,
                             next_generation := NextGeneration,
                             by_device := ByDevice,
                             released_by_device := ReleasedByDevice} = Section,
                           Config)
  when map_size(Section) =:= 5,
       is_binary(AllocatorInstanceId),
       byte_size(AllocatorInstanceId) =:= 12,
       is_integer(NextGeneration), NextGeneration > 0,
       is_map(ByDevice), is_map(ReleasedByDevice) ->
    case valid_allocator_instance_id(AllocatorInstanceId) of
        true ->
            case overlapping_device_state(ByDevice, ReleasedByDevice) of
                {error, _} = OverlapError ->
                    OverlapError;
                ok ->
                    case validate_restored_allocations(
                           maps:to_list(ByDevice),
                           AllocatorInstanceId,
                           NextGeneration,
                           Config,
                           #{},
                           #{}) of
                        {ok, BySlot, Generations} ->
                            case validate_released_allocations(
                                   maps:to_list(ReleasedByDevice),
                                   AllocatorInstanceId,
                                   NextGeneration,
                                   Config,
                                   Generations) of
                                ok -> {ok, Section, BySlot};
                                {error, _} = ReleasedError -> ReleasedError
                            end;
                        {error, _} = ActiveError -> ActiveError
                    end
            end;
        false ->
            {error, invalid_allocator_instance_id}
    end;
validate_allocator_section(#{schema_version := SchemaVersion}, _Config)
  when SchemaVersion =/= ?ALLOCATOR_SCHEMA_VERSION ->
    {error, {unsupported_allocator_schema_version, SchemaVersion}};
validate_allocator_section(_Section, _Config) ->
    {error, invalid_allocator_projection}.

overlapping_device_state(ByDevice, ReleasedByDevice) ->
    case [DeviceId || DeviceId <- maps:keys(ByDevice),
                      maps:is_key(DeviceId, ReleasedByDevice)] of
        [] -> ok;
        [DeviceId | _] -> {error, {duplicate_allocator_device_state, DeviceId}}
    end.

validate_restored_allocations([], _AllocatorInstanceId, _NextGeneration,
                              _Config, BySlot, Generations) ->
    {ok, BySlot, Generations};
validate_restored_allocations([{DeviceId, Allocation} | Rest],
                              AllocatorInstanceId,
                              NextGeneration,
                              Config,
                              BySlot,
                              Generations)
  when is_binary(DeviceId), byte_size(DeviceId) > 0, is_map(Allocation) ->
    case validate_restored_allocation(DeviceId,
                                      Allocation,
                                      AllocatorInstanceId,
                                      NextGeneration,
                                      Config) of
        {ok, Slot, Generation} ->
            case {maps:is_key(Slot, BySlot),
                  maps:is_key(Generation, Generations)} of
                {false, false} ->
                    validate_restored_allocations(
                      Rest,
                      AllocatorInstanceId,
                      NextGeneration,
                      Config,
                      BySlot#{Slot => DeviceId},
                      Generations#{Generation => DeviceId});
                {true, _} ->
                    {error, {duplicate_allocator_slot, Slot}};
                {_, true} ->
                    {error, {duplicate_allocator_generation, Generation}}
            end;
        {error, _} = Error ->
            Error
    end;
validate_restored_allocations([{DeviceId, _Allocation} | _Rest],
                              _AllocatorInstanceId,
                              _NextGeneration,
                              _Config,
                              _BySlot,
                              _Generations) ->
    {error, {invalid_restored_device_allocation, DeviceId}}.

validate_released_allocations([], _AllocatorInstanceId,
                              _NextGeneration, _Config, _Generations) ->
    ok;
validate_released_allocations([{DeviceId, Released} | Rest],
                              AllocatorInstanceId,
                              NextGeneration,
                              Config,
                              Generations)
  when is_binary(DeviceId), byte_size(DeviceId) > 0, is_map(Released) ->
    ReleasedAt = maps:get(released_at, Released, undefined),
    CreatedAt = maps:get(created_at, Released, undefined),
    Generation = maps:get(generation, Released, undefined),
    Reserved = maps:remove(released_at, Released),
    Restored = Reserved#{state => reserved},
    case maps:get(state, Released, undefined) =:= released andalso
         is_integer(ReleasedAt) andalso
         is_integer(CreatedAt) andalso ReleasedAt >= CreatedAt andalso
         not maps:is_key(Generation, Generations) of
        true ->
            case validate_restored_allocation(DeviceId,
                                              Restored,
                                              AllocatorInstanceId,
                                              NextGeneration,
                                              Config) of
                {ok, _Slot, Generation} ->
                    validate_released_allocations(
                      Rest,
                      AllocatorInstanceId,
                      NextGeneration,
                      Config,
                      Generations#{Generation => DeviceId});
                {error, _} = Error -> Error
            end;
        false ->
            case is_integer(Generation) andalso
                 maps:is_key(Generation, Generations) of
                true ->
                    {error, {duplicate_allocator_generation, Generation}};
                false ->
                    {error, {invalid_released_allocation, DeviceId}}
            end
    end;
validate_released_allocations([{DeviceId, _Released} | _Rest],
                              _AllocatorInstanceId,
                              _NextGeneration,
                              _Config,
                              _Generations) ->
    {error, {invalid_released_allocation, DeviceId}}.

validate_restored_allocation(DeviceId,
                             Allocation,
                             AllocatorInstanceId,
                             NextGeneration,
                             Config) ->
    Slot = maps:get(slot, Allocation, undefined),
    Generation = maps:get(generation, Allocation, undefined),
    CreatedAt = maps:get(created_at, Allocation, undefined),
    Capacity = maps:get(capacity, Config),
    case is_integer(Slot) andalso Slot > 0 andalso Slot =< Capacity andalso
         is_integer(Generation) andalso Generation > 0 andalso
         Generation < NextGeneration andalso
         is_integer(CreatedAt) andalso CreatedAt >= 0 of
        false ->
            {error, {invalid_restored_allocation, DeviceId}};
        true ->
            Expected = build_allocation(DeviceId,
                                        Slot,
                                        AllocatorInstanceId,
                                        Generation,
                                        CreatedAt,
                                        Config),
            case Allocation =:= Expected of
                true -> {ok, Slot, Generation};
                false ->
                    {error, {allocator_projection_config_mismatch, DeviceId}}
            end
    end.

state_from_projection(Config, AllocatorSection, BySlot) ->
    #{config => Config,
      allocator_instance_id => maps:get(allocator_instance_id,
                                        AllocatorSection),
      next_generation => maps:get(next_generation, AllocatorSection),
      by_device => maps:get(by_device, AllocatorSection),
      by_slot => BySlot,
      released_by_device => maps:get(released_by_device, AllocatorSection),
      projection_section => AllocatorSection}.

allocator_section(State, ByDevice, ReleasedByDevice, NextGeneration) ->
    #{schema_version => ?ALLOCATOR_SCHEMA_VERSION,
      allocator_instance_id => maps:get(allocator_instance_id, State),
      next_generation => NextGeneration,
      by_device => ByDevice,
      released_by_device => ReleasedByDevice}.

commit_allocator_section(NewSection,
                         State = #{projection_section := ExpectedSection}) ->
    case safe_projection_update(
           fun(Current) when Current =:= ExpectedSection ->
                   NewSection;
              (_Current) ->
                   {error, allocator_projection_conflict}
           end) of
        {ok, _Version, Projection} ->
            committed_state(NewSection, Projection, State);
        {ok, unchanged, _Version, Projection} ->
            committed_state(NewSection, Projection, State);
        {error, Reason} ->
            {error, Reason}
    end.

committed_state(NewSection, Projection, State) ->
    case maps:get(allocator, Projection, undefined) of
        NewSection ->
            {ok, State#{allocator_instance_id =>
                            maps:get(allocator_instance_id, NewSection),
                        next_generation =>
                            maps:get(next_generation, NewSection),
                        by_device => maps:get(by_device, NewSection),
                        released_by_device =>
                            maps:get(released_by_device, NewSection),
                        projection_section => NewSection}};
        _ ->
            {error, invalid_allocator_projection_commit_result}
    end.

safe_projection_get() ->
    try vpn_projection:get() of
        {ok, _Version, _Projection} = Ok -> Ok;
        Other -> {error, {invalid_projection_get_result, Other}}
    catch
        exit:Reason -> {error, {projection_unavailable, Reason}};
        Class:Reason -> {error, {projection_get_failed, Class, Reason}}
    end.

safe_projection_update(Fun) ->
    try vpn_projection:update(allocator, Fun) of
        {ok, _Version, _Projection} = Ok -> Ok;
        {ok, unchanged, _Version, _Projection} = Ok -> Ok;
        {error, _Reason} = Error -> Error;
        Other -> {error, {invalid_projection_update_result, Other}}
    catch
        exit:Reason -> {error, {projection_unavailable, Reason}};
        Class:Reason -> {error, {projection_update_failed, Class, Reason}}
    end.

first_free_slot(Slot, Capacity, _BySlot) when Slot > Capacity ->
    {error, exhausted};
first_free_slot(Slot, Capacity, BySlot) ->
    case maps:is_key(Slot, BySlot) of
        true -> first_free_slot(Slot + 1, Capacity, BySlot);
        false -> {ok, Slot}
    end.

build_allocation(DeviceId,
                 Slot,
                 AllocatorInstanceId,
                 Generation,
                 CreatedAt,
                 Config) ->
    SlotSuffix = integer_to_binary(Slot),
    GenerationSuffix = integer_to_binary(Generation),
    PeerSuffix = <<SlotSuffix/binary, "_", AllocatorInstanceId/binary,
                   "_", GenerationSuffix/binary>>,
    ClientPeerId = prefixed_binary(client_peer_prefix, PeerSuffix, Config),
    GatewayPeerId = prefixed_binary(gateway_peer_prefix, PeerSuffix, Config),
    ClientIfName = prefixed_binary(client_ifname_prefix, SlotSuffix, Config),
    GatewayIfName = prefixed_binary(gateway_ifname_prefix, SlotSuffix, Config),
    Host = maps:get(first_host, Config) + Slot - 1,
    ClientIp = ip_string(maps:get(client_network, Config), Host),
    GatewayIp = ip_string(maps:get(gateway_network, Config), Host),
    ClientPort = maps:get(client_udp_port_base, Config) + Slot - 1,
    GatewayPort = maps:get(gateway_udp_port_base, Config) + Slot - 1,
    RemoteIp = maps:get(remote_ip, Config),
    #{allocation_id => <<"dynamic-vpn-", PeerSuffix/binary>>,
      device_id => DeviceId,
      slot => Slot,
      generation => Generation,
      allocator_instance_id => AllocatorInstanceId,
      state => reserved,
      persistence => durable,
      client_peer_id => ClientPeerId,
      gateway_peer_id => GatewayPeerId,
      client => #{peer_id => ClientPeerId,
                  ifname => ClientIfName,
                  ip => ClientIp,
                  local_udp_port => ClientPort,
                  remote_peer_id => GatewayPeerId,
                  remote_ip => RemoteIp,
                  remote_udp_port => GatewayPort},
      gateway => #{peer_id => GatewayPeerId,
                   ifname => GatewayIfName,
                   ip => GatewayIp,
                   local_udp_port => GatewayPort,
                   remote_peer_id => ClientPeerId,
                   remote_ip => RemoteIp,
                   remote_udp_port => ClientPort},
      created_at => CreatedAt}.

new_allocator_instance_id() ->
    hex_binary(crypto:strong_rand_bytes(6)).

valid_allocator_instance_id(AllocatorInstanceId) ->
    lists:all(fun is_hex_digit/1, binary_to_list(AllocatorInstanceId)).

is_hex_digit(Char) when Char >= $0, Char =< $9 -> true;
is_hex_digit(Char) when Char >= $a, Char =< $f -> true;
is_hex_digit(_Char) -> false.

hex_binary(Binary) ->
    list_to_binary([hex_byte(Byte) || <<Byte>> <= Binary]).

hex_byte(Byte) ->
    [hex_digit(Byte bsr 4), hex_digit(Byte band 16#0f)].

hex_digit(Value) when Value < 10 ->
    $0 + Value;
hex_digit(Value) ->
    $a + Value - 10.

prefixed_binary(Key, Suffix, Config) ->
    Prefix = maps:get(Key, Config),
    <<Prefix/binary, Suffix/binary>>.

ip_string({A, B, C}, Host) ->
    lists:flatten(io_lib:format("~B.~B.~B.~B", [A, B, C, Host])).

compare_allocations(#{slot := A}, #{slot := B}) ->
    A =< B.

load_config() ->
    Defaults = #{capacity => 200,
                 first_host => 10,
                 client_network => {10, 30, 0},
                 gateway_network => {10, 31, 0},
                 client_udp_port_base => 20000,
                 gateway_udp_port_base => 30000,
                 client_peer_prefix => <<"client_dyn_">>,
                 gateway_peer_prefix => <<"gateway_dyn_">>,
                 client_ifname_prefix => <<"vpc">>,
                 gateway_ifname_prefix => <<"vpg">>,
                 remote_ip => {127, 0, 0, 1}},
    case application:get_env(vpn, dynamic_peer_allocator, #{}) of
        UserConfig when is_map(UserConfig) ->
            Config = maps:merge(Defaults, UserConfig),
            case validate_config(Config) of
                ok -> {ok, Config};
                {error, _} = Error -> Error
            end;
        _Other ->
            {error, invalid_config_type}
    end.

validate_config(Config) ->
    Capacity = maps:get(capacity, Config, undefined),
    FirstHost = maps:get(first_host, Config, undefined),
    ClientPortBase = maps:get(client_udp_port_base, Config, undefined),
    GatewayPortBase = maps:get(gateway_udp_port_base, Config, undefined),
    case is_integer(Capacity) andalso Capacity > 0 of
        false -> {error, invalid_capacity};
        true ->
            case is_integer(FirstHost) andalso FirstHost > 0 andalso
                 FirstHost + Capacity - 1 =< 254 of
                false -> {error, invalid_host_range};
                true ->
                    validate_networks_and_ports(Config,
                                                Capacity,
                                                ClientPortBase,
                                                GatewayPortBase)
            end
    end.

validate_networks_and_ports(Config, Capacity, ClientPortBase, GatewayPortBase) ->
    ClientNetwork = maps:get(client_network, Config, undefined),
    GatewayNetwork = maps:get(gateway_network, Config, undefined),
    case valid_network(ClientNetwork) andalso
         valid_network(GatewayNetwork) andalso
         ClientNetwork =/= GatewayNetwork andalso
         valid_remote_ip(maps:get(remote_ip, Config, undefined)) of
        false ->
            {error, invalid_network};
        true ->
            case valid_port_range(ClientPortBase, Capacity) andalso
                 valid_port_range(GatewayPortBase, Capacity) of
                false ->
                    {error, invalid_udp_port_range};
                true ->
                    case port_ranges_overlap(ClientPortBase,
                                             GatewayPortBase,
                                             Capacity) of
                        true -> {error, overlapping_udp_port_ranges};
                        false -> validate_prefixes(Config, Capacity)
                    end
            end
    end.

validate_prefixes(Config, Capacity) ->
    BinaryKeys = [client_peer_prefix,
                  gateway_peer_prefix,
                  client_ifname_prefix,
                  gateway_ifname_prefix],
    case lists:all(fun(Key) ->
                           Value = maps:get(Key, Config, undefined),
                           is_binary(Value) andalso byte_size(Value) > 0
                   end,
                   BinaryKeys) of
        false ->
            {error, invalid_prefix};
        true ->
            ClientPeerPrefix = maps:get(client_peer_prefix, Config),
            GatewayPeerPrefix = maps:get(gateway_peer_prefix, Config),
            ClientIfNamePrefix = maps:get(client_ifname_prefix, Config),
            GatewayIfNamePrefix = maps:get(gateway_ifname_prefix, Config),
            case ClientPeerPrefix =/= GatewayPeerPrefix andalso
                 ClientIfNamePrefix =/= GatewayIfNamePrefix of
                false ->
                    {error, overlapping_prefixes};
                true ->
                    MaxSuffix = integer_to_binary(Capacity),
                    ClientIfName = prefixed_binary(client_ifname_prefix,
                                                   MaxSuffix,
                                                   Config),
                    GatewayIfName = prefixed_binary(gateway_ifname_prefix,
                                                    MaxSuffix,
                                                    Config),
                    case byte_size(ClientIfName) =< 15 andalso
                         byte_size(GatewayIfName) =< 15 of
                        true -> ok;
                        false -> {error, ifname_too_long}
                    end
            end
    end.

valid_network({A, B, C}) ->
    valid_octet(A) andalso valid_octet(B) andalso valid_octet(C);
valid_network(_) ->
    false.

valid_remote_ip({A, B, C, D}) ->
    valid_octet(A) andalso valid_octet(B) andalso
    valid_octet(C) andalso valid_octet(D);
valid_remote_ip(_) ->
    false.

valid_octet(Value) ->
    is_integer(Value) andalso Value >= 0 andalso Value =< 255.

valid_port_range(Base, Capacity) ->
    is_integer(Base) andalso Base > 0 andalso Base + Capacity - 1 =< 65535.

port_ranges_overlap(BaseA, BaseB, Capacity) ->
    EndA = BaseA + Capacity - 1,
    EndB = BaseB + Capacity - 1,
    not (EndA < BaseB orelse EndB < BaseA).
