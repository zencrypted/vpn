%%%-------------------------------------------------------------------
%% @doc Volatile reservation allocator for dynamic VPN peer pairs.
%%
%% The allocator owns transport resource selection. IAS supplies only a stable
%% Device identifier. Reservations are idempotent per Device while this process
%% remains alive and use binary peer identifiers to avoid dynamic atom creation.
%%
%% This first stage does not create certificates, runtime configurations, or
%% peer processes. Allocations are intentionally lost when the VPN node stops.
%%%-------------------------------------------------------------------
-module(vpn_peer_allocator).

-behaviour(gen_server).

-export([start_link/0,
         ensure/1,
         lookup/1,
         release/1,
         list/0,
         status/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).

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
            {ok, #{config => Config,
                   allocator_instance_id => new_allocator_instance_id(),
                   by_device => #{},
                   by_slot => #{}}};
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
handle_call({release, DeviceId}, _From,
            State = #{by_device := ByDevice, by_slot := BySlot}) ->
    case maps:take(DeviceId, ByDevice) of
        {Allocation, RemainingByDevice} ->
            Slot = maps:get(slot, Allocation),
            RemainingBySlot = maps:remove(Slot, BySlot),
            Released = Allocation#{state => released,
                                     released_at => erlang:system_time(second)},
            {reply, {ok, Released},
             State#{by_device => RemainingByDevice,
                    by_slot => RemainingBySlot}};
        error ->
            {reply, {error, not_found}, State}
    end;
handle_call(list, _From, State = #{by_device := ByDevice}) ->
    Allocations = maps:values(ByDevice),
    Sorted = lists:sort(fun compare_allocations/2, Allocations),
    {reply, Sorted, State};
handle_call(status, _From,
            State = #{config := Config, by_device := ByDevice}) ->
    Capacity = maps:get(capacity, Config),
    Allocated = map_size(ByDevice),
    {reply, #{persistence => volatile,
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
                  by_device := ByDevice,
                  by_slot := BySlot}) ->
    Capacity = maps:get(capacity, Config),
    case first_free_slot(1, Capacity, BySlot) of
        {ok, Slot} ->
            Allocation = build_allocation(DeviceId,
                                          Slot,
                                          AllocatorInstanceId,
                                          Config),
            {reply, {ok, Allocation},
             State#{by_device => ByDevice#{DeviceId => Allocation},
                    by_slot => BySlot#{Slot => DeviceId}}};
        {error, exhausted} = Error ->
            {reply, Error, State}
    end.

first_free_slot(Slot, Capacity, _BySlot) when Slot > Capacity ->
    {error, exhausted};
first_free_slot(Slot, Capacity, BySlot) ->
    case maps:is_key(Slot, BySlot) of
        true -> first_free_slot(Slot + 1, Capacity, BySlot);
        false -> {ok, Slot}
    end.

build_allocation(DeviceId, Slot, AllocatorInstanceId, Config) ->
    SlotSuffix = integer_to_binary(Slot),
    Generation = erlang:unique_integer([positive, monotonic]),
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
      persistence => volatile,
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
      created_at => erlang:system_time(second)}.


new_allocator_instance_id() ->
    hex_binary(crypto:strong_rand_bytes(6)).

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
