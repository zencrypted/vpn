%%%-------------------------------------------------------------------
%% @doc Top-level supervisor for vpn.
%%%-------------------------------------------------------------------
-module(vpn_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 1,
        period => 5
    },
    ChildSpecs = [
        #{id => vpn_peer_sup,
          start => {vpn_peer_sup, start_link, []},
          restart => permanent,
          shutdown => infinity,
          type => supervisor,
          modules => [vpn_peer_sup]},
        #{id => vpn_http,
          start => {vpn_http, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [vpn_http]}
    ],
    {ok, {SupFlags, ChildSpecs}}.
