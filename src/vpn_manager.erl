%%%-------------------------------------------------------------------
%% @doc Read-only VPN management API.
%%%-------------------------------------------------------------------
-module(vpn_manager).

-export([list_peers/0,
         running_peers/0,
         status/0,
         peer_status/1,
         peer_info/1,
         peer_stats/1,
         start_peer/1,
         stop_peer/1,
         reload_config/0,
         peer_running/1,
         find_peer/1]).

list_peers() ->
    configured_peer_ids().

running_peers() ->
    running_peer_ids().

status() ->
    Configured = list_peers(),
    Running = running_peers(),
    #{configured => Configured,
      running => Running,
      peers => maps:from_list([{PeerId, peer_status(PeerId)} || PeerId <- Configured])}.

peer_status(PeerId) ->
    case lists:member(PeerId, running_peers()) of
        true ->
            running_peer_status(PeerId);
        false ->
            #{running => false}
    end.

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

running_peer_status(PeerId) ->
    case peer_info(PeerId) of
        #{identity := Identity, config := Config} ->
            case peer_stats(PeerId) of
                #{id := _PeerId} = Stats ->
                    #{running => true,
                      identity => Identity,
                      config => Config,
                      stats => Stats};
                {error, Reason} ->
                    #{running => false,
                      error => Reason}
            end;
        {error, Reason} ->
            #{running => false,
              error => Reason}
    end.

reload_config() ->
    ConfiguredIds = configured_peer_ids(),
    RunningIds = running_peer_ids(),
    ToStop = RunningIds -- ConfiguredIds,
    ToStart = ConfiguredIds -- RunningIds,
    Unchanged = RunningIds -- ToStop,
    StopResult = collect_stop_results(ToStop, #{started => [], stopped => [], failed => []}),
    StartResult = collect_start_results(ToStart, StopResult),
    StartResult#{unchanged => Unchanged}.

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
                {error, {Reason, {child, _Pid, _Id, _Start, _Restart, _Significant, _Shutdown, _Type, _Modules}}} ->
                    {error, Reason};
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

collect_stop_results([], Acc) ->
    Acc;
collect_stop_results([PeerId | Rest], Acc) ->
    case stop_peer(PeerId) of
        ok ->
            collect_stop_results(Rest, append_result(stopped, PeerId, Acc));
        {error, Reason} ->
            collect_stop_results(Rest, append_result(failed, {PeerId, Reason}, Acc))
    end.

collect_start_results([], Acc) ->
    Acc;
collect_start_results([PeerId | Rest], Acc) ->
    case start_peer(PeerId) of
        {ok, _Pid} ->
            collect_start_results(Rest, append_result(started, PeerId, Acc));
        {error, Reason} ->
            collect_start_results(Rest, append_result(failed, {PeerId, Reason}, Acc))
    end.

append_result(Key, Value, Acc) ->
    maps:update_with(Key, fun(Values) -> Values ++ [Value] end, [Value], Acc).

configured_peer_ids() ->
    lists:sort([maps:get(id, PeerConfig) || PeerConfig <- configured_peers()]).

running_peer_ids() ->
    lists:sort([PeerId || {{vpn_peer, PeerId}, Pid, worker, _Modules} <- peer_children(),
                          is_pid(Pid)]).

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
