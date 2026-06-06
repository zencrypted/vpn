%%%-------------------------------------------------------------------
%% @doc Read-only VPN management API.
%%%-------------------------------------------------------------------
-module(vpn_manager).

-export([list_peers/0, peer_info/1, peer_stats/1, find_peer/1]).

list_peers() ->
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

find_peer(PeerId) ->
    case [Pid || {{vpn_peer, Id}, Pid, worker, _Modules} <- peer_children(),
                 Id =:= PeerId,
                 is_pid(Pid)] of
        [Pid | _] ->
            {ok, Pid};
        [] ->
            {error, not_found}
    end.

peer_children() ->
    try supervisor:which_children(vpn_peer_sup) of
        Children ->
            Children
    catch
        exit:{noproc, _} ->
            []
    end.
