%%%-------------------------------------------------------------------
%% @doc Read-only VPN management API.
%%%-------------------------------------------------------------------
-module(vpn_manager).

-export([list_peers/0,
         running_peers/0,
         peer_info/1,
         peer_stats/1,
         start_peer/1,
         stop_peer/1,
         peer_running/1,
         find_peer/1]).

list_peers() ->
    [maps:get(id, PeerConfig) || PeerConfig <- configured_peers()].

running_peers() ->
    [PeerId || {{vpn_peer, PeerId}, Pid, worker, _Modules} <- peer_children(),
               is_pid(Pid)].

peer_info(PeerId) ->
    case find_peer(PeerId) of
        {ok, Pid} ->
            #{id => PeerId,
              identity => vpn_peer:identity_info(Pid),
              config => vpn_peer:config(Pid)};
        {error, not_found} ->
            {error, not_found}
    end.

peer_stats(PeerId) ->
    case find_peer(PeerId) of
        {ok, Pid} ->
            vpn_peer:stats(Pid);
        {error, not_found} ->
            {error, not_found}
    end.

start_peer(PeerId) ->
    case peer_running(PeerId) of
        true ->
            {error, already_started};
        false ->
            start_configured_peer(PeerId)
    end.

stop_peer(PeerId) ->
    case find_peer(PeerId) of
        {ok, _Pid} ->
            vpn_peer_sup:stop_peer(PeerId);
        {error, not_found} ->
            {error, not_found}
    end.

peer_running(PeerId) ->
    case find_peer(PeerId) of
        {ok, _Pid} ->
            true;
        {error, not_found} ->
            false
    end.

find_peer(PeerId) ->
    case [Pid || {{vpn_peer, Id}, Pid, worker, _Modules} <- peer_children(),
                 Id =:= PeerId,
                 is_pid(Pid)] of
        [Pid | _] ->
            {ok, Pid};
        [] ->
            {error, not_found}
    end.

start_configured_peer(PeerId) ->
    case find_peer_config(PeerId) of
        {ok, PeerConfig} ->
            case vpn_peer_sup:start_peer(PeerConfig) of
                {ok, Pid} ->
                    {ok, Pid};
                {ok, Pid, _Info} ->
                    {ok, Pid};
                {error, {already_started, _Pid}} ->
                    {error, already_started};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, not_found} ->
            {error, not_found}
    end.

find_peer_config(PeerId) ->
    case [PeerConfig || PeerConfig <- configured_peers(),
                        maps:get(id, PeerConfig) =:= PeerId] of
        [PeerConfig | _] ->
            {ok, PeerConfig};
        [] ->
            {error, not_found}
    end.

configured_peers() ->
    application:get_env(vpn, peers, []).

peer_children() ->
    try supervisor:which_children(vpn_peer_sup) of
        Children ->
            Children
    catch
        exit:{noproc, _} ->
            []
    end.
