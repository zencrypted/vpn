-module(vpn_manager_tests).

-include_lib("eunit/include/eunit.hrl").

-export([init/1]).
-export([start_peer/1]).
-export([handle_call/3, handle_cast/2, handle_info/2]).

manager_test_() ->
    {setup,
     fun start_peer_sup/0,
     fun stop_peer_sup/1,
     fun(_SupPid) ->
             [?_assertEqual([peer_a, peer_b], lists:sort(vpn_manager:list_peers())),
              ?_assertMatch(#{id := peer_a,
                              identity := #{peer_id := peer_a},
                              config := #{id := peer_a}},
                            vpn_manager:peer_info(peer_a)),
              ?_assertMatch(#{id := peer_a,
                              link := #{tun_rx_packets := 0}},
                            vpn_manager:peer_stats(peer_a)),
              ?_assertEqual({error, not_found}, vpn_manager:peer_info(unknown_peer)),
              ?_assertEqual({error, not_found}, vpn_manager:peer_stats(unknown_peer)),
              ?_assertEqual({error, not_found}, vpn_manager:find_peer(unknown_peer))]
     end}.

start_peer_sup() ->
    {ok, SupPid} = supervisor:start_link({local, vpn_peer_sup},
                                         ?MODULE,
                                         {supervisor, [peer_a, peer_b]}),
    SupPid.

stop_peer_sup(SupPid) ->
    unlink(SupPid),
    exit(SupPid, shutdown),
    ok.

init({supervisor, PeerIds}) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 5,
        period => 10
    },
    ChildSpecs = [peer_child_spec(PeerId) || PeerId <- PeerIds],
    {ok, {SupFlags, ChildSpecs}};
init({peer, PeerId}) ->
    {ok, #{id => PeerId}}.

start_peer(PeerId) ->
    gen_server:start_link(?MODULE, {peer, PeerId}, []).

handle_call(identity_info, _From, State = #{id := PeerId}) ->
    {reply, #{peer_id => PeerId,
              certificate_path => "priv/certs/" ++ atom_to_list(PeerId) ++ ".crt",
              private_key_path => "priv/certs/" ++ atom_to_list(PeerId) ++ ".key"},
     State};
handle_call(config, _From, State = #{id := PeerId}) ->
    {reply, #{id => PeerId,
              mode => tun,
              ifname => list_to_binary(atom_to_list(PeerId)),
              ip => "10.20.20.1"},
     State};
handle_call(stats, _From, State = #{id := PeerId}) ->
    {reply, #{id => PeerId,
              link => #{tun_rx_packets => 0,
                        udp_tx_packets => 0}},
     State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Message, State) ->
    {noreply, State}.

peer_child_spec(PeerId) ->
    #{id => {vpn_peer, PeerId},
      start => {?MODULE, start_peer, [PeerId]},
      restart => permanent,
      shutdown => 5000,
      type => worker,
      modules => [vpn_peer]}.
