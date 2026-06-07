%%%-------------------------------------------------------------------
%% @doc Minimal Cowboy HTTP listener for vpn administration endpoints.
%%%-------------------------------------------------------------------
-module(vpn_http).

-export([start_link/0,
         stop/0]).

-define(LISTENER, ?MODULE).
-define(DEFAULT_PORT, 8080).

start_link() ->
    Port = application:get_env(vpn, http_port, ?DEFAULT_PORT),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/", vpn_dashboard_http, []},
            {"/admin", vpn_dashboard_http, []},
            {"/admin/peer/:id/start", vpn_peer_action_http, #{action => start}},
            {"/admin/peer/:id/stop", vpn_peer_action_http, #{action => stop}},
            {"/admin/reload", vpn_reload_http, []},
            {"/api/admin/summary", vpn_admin_http, []}
        ]}
    ]),
    cowboy:start_clear(?LISTENER,
                       [{port, Port}],
                       #{env => #{dispatch => Dispatch}}).

stop() ->
    cowboy:stop_listener(?LISTENER).
