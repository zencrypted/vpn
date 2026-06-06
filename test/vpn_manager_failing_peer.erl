-module(vpn_manager_failing_peer).

-export([start_link/1]).

start_link(_Config) ->
    {error, test_start_failed}.
