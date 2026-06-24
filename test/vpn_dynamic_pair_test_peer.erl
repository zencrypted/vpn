-module(vpn_dynamic_pair_test_peer).

-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

start_link(Config) ->
    Role = maps:get(allocation_role, Config, undefined),
    case application:get_env(vpn, dynamic_pair_test_fail_role) of
        {ok, Role} ->
            {error, {dynamic_pair_test_start_failed, Role}};
        _ ->
            gen_server:start_link(?MODULE, Config, [])
    end.

init(Config) ->
    {ok, Config}.

handle_call(stats, _From, State = #{id := PeerId}) ->
    {reply, #{id => PeerId,
              link => #{handshake => #{status => established}}},
     State};
handle_call(identity_info, _From, State = #{id := PeerId}) ->
    {reply, #{peer_id => PeerId,
              trusted => true,
              key_match => true,
              certificate => #{}},
     State};
handle_call(config, _From, State) ->
    {reply, maps:with([id,
                       mode,
                       ifname,
                       ip,
                       local_udp_port,
                       remote_ip,
                       remote_udp_port,
                       remote_peer_id,
                       device_id,
                       allocation_id,
                       allocator_instance_id,
                       allocation_slot,
                       allocation_generation,
                       allocation_role,
                       profile_id,
                       authorization_mode,
                       authorized,
                       authorization_reason],
                      State),
     State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.
