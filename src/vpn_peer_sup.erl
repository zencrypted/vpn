%%%-------------------------------------------------------------------
%% @doc Supervisor for configured vpn peers.
%%%-------------------------------------------------------------------
-module(vpn_peer_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

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
    #{id => {vpn_peer, PeerId},
      start => {vpn_peer, start_link, [PeerConfig]},
      restart => permanent,
      shutdown => 5000,
      type => worker,
      modules => [vpn_peer]}.
