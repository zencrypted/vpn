%%%-------------------------------------------------------------------
%% @doc Supervisor for configured vpn peers.
%%%-------------------------------------------------------------------
-module(vpn_peer_sup).

-behaviour(supervisor).

-export([start_link/0, start_peer/1, stop_peer/1]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_peer(PeerConfig) ->
    supervisor:start_child(?SERVER, peer_child_spec(PeerConfig)).

stop_peer(PeerId) ->
    ChildId = {vpn_peer, PeerId},
    case supervisor:terminate_child(?SERVER, ChildId) of
        ok ->
            supervisor:delete_child(?SERVER, ChildId);
        {error, Reason} ->
            {error, Reason}
    end.

init([]) ->
    Peers = application:get_env(vpn, peers, []),
    SupFlags = #{
        strategy => one_for_one,
        intensity => 5,
        period => 10
    },
    ChildSpecs = [peer_child_spec(PeerConfig) || PeerConfig <- Peers],
    {ok, {SupFlags, ChildSpecs}}.

peer_child_spec(PeerConfig) ->
    PeerId = maps:get(id, PeerConfig),
    PeerModule = maps:get(peer_module, PeerConfig, vpn_peer),
    #{id => {vpn_peer, PeerId},
      start => {PeerModule, start_link, [PeerConfig]},
      restart => permanent,
      shutdown => 5000,
      type => worker,
      modules => [PeerModule]}.
