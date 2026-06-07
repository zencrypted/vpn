%%%-------------------------------------------------------------------
%% @doc Read-only administration facade.
%%%-------------------------------------------------------------------
-module(vpn_admin).

-export([dashboard/0, overview/0, peer_counts/0]).

dashboard() ->
    #{status => vpn_manager:status(),
      certificates => vpn_manager:certificates()}.

overview() ->
    Counts = peer_counts(),
    #{configured_peers => maps:get(configured, Counts),
      running_peers => maps:get(running, Counts),
      stopped_peers => maps:get(stopped, Counts),
      certificates => length(vpn_manager:certificates())}.

peer_counts() ->
    Configured = length(vpn_manager:list_peers()),
    Running = length(vpn_manager:running_peers()),
    #{configured => Configured,
      running => Running,
      stopped => Configured - Running}.
