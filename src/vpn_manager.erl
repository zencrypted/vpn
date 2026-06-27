%%%-------------------------------------------------------------------
%% @doc VPN runtime management and explicit registry reconciliation API.
%%%-------------------------------------------------------------------
-module(vpn_manager).

-export([list_peers/0,
         running_peers/0,
         status/0,
         peer_status/1,
         certificates/0,
         certificate_info/1,
         certificate_status/1,
         peer_info/1,
         peer_stats/1,
         rekey/1, debug_frame_history/1, debug_replay_frame/3, debug_send_frames/2,
         debug_send_payload/2, debug_send_payloads/3,
         debug_received_payloads/1, debug_clear_received_payloads/1,
         debug_session_state/1, debug_wait_for_epoch/3,
         debug_peer_pid/1, debug_restart_peer/1, debug_wait_for_peer_restart/3,
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

certificates() ->
    [certificate_status(PeerId) || PeerId <- list_peers()].

certificate_info(PeerId) ->
    case lists:member(PeerId, list_peers()) of
        true ->
            certificate_status(PeerId);
        false ->
            {error, not_found}
    end.

certificate_status(PeerId) ->
    case lists:member(PeerId, running_peers()) of
        true ->
            running_certificate_status(PeerId);
        false ->
            stopped_certificate_status(PeerId)
    end.

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
            try
                #{id => PeerId,
                  identity => vpn_peer:identity_info(Pid),
                  config => vpn_peer:config(Pid)}
            catch
                exit:Reason:Stacktrace ->
                    case peer_disappeared_during_call(Reason) of
                        true -> {error, not_found};
                        false -> erlang:raise(exit, Reason, Stacktrace)
                    end
            end;
        {error, not_found} ->
            {error, not_found}
    end.

peer_disappeared_during_call(noproc) -> true;
peer_disappeared_during_call(normal) -> true;
peer_disappeared_during_call(shutdown) -> true;
peer_disappeared_during_call(killed) -> true;
peer_disappeared_during_call({noproc, _Call}) -> true;
peer_disappeared_during_call({normal, _Call}) -> true;
peer_disappeared_during_call({shutdown, _Call}) -> true;
peer_disappeared_during_call({killed, _Call}) -> true;
peer_disappeared_during_call(_Reason) -> false.

peer_stats(PeerId) ->
    case find_peer(PeerId) of
        {ok, Pid} ->
            vpn_peer:stats(Pid);
        {error, not_found} ->
            {error, not_found}
    end.

rekey(PeerId) ->
    case find_peer(PeerId) of
        {ok, Pid} -> vpn_peer:rekey(Pid);
        {error, not_found} -> {error, not_found}
    end.

debug_frame_history(PeerId) ->
    case find_peer(PeerId) of
        {ok, Pid} -> vpn_peer:debug_frame_history(Pid);
        {error, not_found} -> {error, not_found}
    end.

debug_replay_frame(PeerId, KeyEpoch, Seq) ->
    case find_peer(PeerId) of
        {ok, Pid} -> vpn_peer:debug_replay_frame(Pid, KeyEpoch, Seq);
        {error, not_found} -> {error, not_found}
    end.

debug_send_frames(PeerId, Count) ->
    case find_peer(PeerId) of
        {ok, Pid} -> vpn_peer:debug_send_frames(Pid, Count);
        {error, not_found} -> {error, not_found}
    end.

debug_send_payload(PeerId, Payload) when is_binary(Payload) ->
    case find_peer(PeerId) of
        {ok, Pid} -> vpn_peer:debug_send_payload(Pid, Payload);
        {error, not_found} -> {error, not_found}
    end.

debug_send_payloads(PeerId, Payloads, SendOrder) ->
    case find_peer(PeerId) of
        {ok, Pid} -> vpn_peer:debug_send_payloads(Pid, Payloads, SendOrder);
        {error, not_found} -> {error, not_found}
    end.

debug_received_payloads(PeerId) ->
    case find_peer(PeerId) of
        {ok, Pid} -> vpn_peer:debug_received_payloads(Pid);
        {error, not_found} -> {error, not_found}
    end.

debug_clear_received_payloads(PeerId) ->
    case find_peer(PeerId) of
        {ok, Pid} -> vpn_peer:debug_clear_received_payloads(Pid);
        {error, not_found} -> {error, not_found}
    end.

debug_session_state(PeerId) ->
    case find_peer(PeerId) of
        {ok, Pid} -> vpn_peer:debug_session_state(Pid);
        {error, not_found} -> {error, not_found}
    end.

debug_wait_for_epoch(PeerId, ExpectedEpoch, TimeoutMs)
  when is_integer(ExpectedEpoch), ExpectedEpoch >= 0,
       is_integer(TimeoutMs), TimeoutMs >= 0 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    wait_for_epoch(PeerId, ExpectedEpoch, Deadline).

debug_peer_pid(PeerId) ->
    case debug_controls_enabled(PeerId) of
        true -> find_peer(PeerId);
        false -> {error, debug_replay_controls_disabled};
        {error, _} = Error -> Error
    end.

debug_restart_peer(PeerId) ->
    case debug_peer_pid(PeerId) of
        {ok, OldPid} ->
            case stop_peer(PeerId) of
                ok ->
                    case start_peer(PeerId) of
                        {ok, NewPid} when is_pid(NewPid), NewPid =/= OldPid ->
                            {ok, OldPid};
                        {ok, OldPid} ->
                            {error, {peer_restart_failed, pid_not_replaced}};
                        {error, Reason} ->
                            {error, {peer_restart_failed, Reason}}
                    end;
                {error, Reason} ->
                    {error, {peer_restart_failed, Reason}}
            end;
        {error, _} = Error ->
            Error
    end.

debug_wait_for_peer_restart(PeerId, OldPid, TimeoutMs)
  when is_pid(OldPid), is_integer(TimeoutMs), TimeoutMs >= 0 ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    wait_for_peer_restart(PeerId, OldPid, Deadline).

wait_for_epoch(PeerId, ExpectedEpoch, Deadline) ->
    case debug_session_state(PeerId) of
        {ok, #{current_epoch := ExpectedEpoch} = SessionState} ->
            {ok, SessionState};
        {ok, SessionState} ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> {error, {epoch_wait_timeout, ExpectedEpoch, SessionState}};
                false -> timer:sleep(25), wait_for_epoch(PeerId, ExpectedEpoch, Deadline)
            end;
        {error, _} = Error ->
            Error
    end.

wait_for_peer_restart(PeerId, OldPid, Deadline) ->
    case find_peer(PeerId) of
        {ok, NewPid} when NewPid =/= OldPid ->
            {ok, NewPid};
        _ ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> {error, {peer_restart_timeout, PeerId, OldPid}};
                false -> timer:sleep(25), wait_for_peer_restart(PeerId, OldPid, Deadline)
            end
    end.

debug_controls_enabled(PeerId) ->
    case find_peer_config(PeerId) of
        {ok, PeerConfig} -> maps:get(debug_replay_controls, PeerConfig, false);
        {error, _} = Error -> Error
    end.

running_peer_status(PeerId) ->
    case peer_info(PeerId) of
        #{identity := Identity, config := Config} ->
            case peer_stats(PeerId) of
                #{id := _PeerId} = Stats ->
                    #{running => true,
                      identity => Identity,
                      config => Config,
                      stats => Stats,
                      certificate => certificate_summary(Identity)};
                {error, Reason} ->
                    #{running => false,
                      error => Reason}
            end;
        {error, Reason} ->
            #{running => false,
              error => Reason}
    end.

running_certificate_status(PeerId) ->
    case peer_info(PeerId) of
        #{identity := Identity} ->
            certificate_entry(PeerId, true, Identity);
        {error, Reason} ->
            #{peer_id => PeerId,
              running => false,
              error => Reason}
    end.

stopped_certificate_status(PeerId) ->
    case find_peer_config(PeerId) of
        {ok, PeerConfig} ->
            case configured_identity(PeerConfig) of
                {ok, Identity} ->
                    certificate_entry(PeerId, false, Identity);
                {error, Reason} ->
                    #{peer_id => PeerId,
                      running => false,
                      error => Reason}
            end;
        {error, not_found} ->
            #{peer_id => PeerId,
              running => false,
              error => not_found}
    end.


configured_identity(#{ovpn_identity := Identity}) ->
    {ok, vpn_ovpn_identity:safe_info(Identity)};
configured_identity(PeerConfig) ->
    case vpn_identity:load(PeerConfig) of
        {ok, Identity} -> {ok, vpn_identity:safe_info(Identity)};
        {error, _} = Error -> Error
    end.

certificate_entry(PeerId, Running, Identity) ->
    Certificate = maps:get(certificate, Identity, #{}),
    #{peer_id => PeerId,
      running => Running,
      trusted => maps:get(trusted, Identity, false),
      key_match => maps:get(key_match, Identity, false),
      subject => maps:get(subject, Certificate, undefined),
      issuer => maps:get(issuer, Certificate, undefined),
      serial_number => maps:get(serial_number, Certificate, undefined),
      not_before => maps:get(not_before, Certificate, undefined),
      not_after => maps:get(not_after, Certificate, undefined),
      certificate_path => maps:get(certificate_path, Identity, undefined)}.

certificate_summary(Identity) ->
    Certificate = maps:get(certificate, Identity, #{}),
    #{trusted => maps:get(trusted, Identity, false),
      key_match => maps:get(key_match, Identity, false),
      subject => maps:get(subject, Certificate, undefined),
      issuer => maps:get(issuer, Certificate, undefined),
      serial_number => maps:get(serial_number, Certificate, undefined),
      not_before => maps:get(not_before, Certificate, undefined),
      not_after => maps:get(not_after, Certificate, undefined),
      certificate_path => maps:get(certificate_path, Identity, undefined)}.

reload_config() ->
    ConfiguredIds = desired_peer_ids(),
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
        {error, not_found} ->
            {error, not_found};
        {ok, _PeerConfig} ->
            case peer_enabled(PeerId) of
                false ->
                    {error, disabled};
                true ->
                    start_enabled_peer(PeerId)
            end
    end.

start_enabled_peer(PeerId) ->
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
    case whereis(vpn_peer_registry) of
        undefined ->
            case [PeerConfig || PeerConfig <- configured_peers(),
                                maps:get(id, PeerConfig) =:= PeerId] of
                [PeerConfig | _] -> {ok, PeerConfig};
                [] -> {error, not_found}
            end;
        _Pid ->
            vpn_peer_registry:config(PeerId)
    end.

peer_enabled(PeerId) ->
    case whereis(vpn_peer_registry) of
        undefined ->
            lists:member(PeerId, configured_peer_ids());
        _Pid ->
            case vpn_peer_registry:get(PeerId) of
                {ok, #{enabled := Enabled}} -> Enabled;
                {error, not_found} -> false
            end
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
    case whereis(vpn_peer_registry) of
        undefined ->
            lists:sort([maps:get(id, PeerConfig) || PeerConfig <- configured_peers()]);
        _Pid ->
            [maps:get(id, Entry) || Entry <- vpn_peer_registry:list()]
    end.

desired_peer_ids() ->
    case whereis(vpn_peer_registry) of
        undefined ->
            configured_peer_ids();
        _Pid ->
            lists:sort([maps:get(id, PeerConfig)
                        || PeerConfig <- vpn_peer_registry:enabled_configs()])
    end.

running_peer_ids() ->
    lists:sort([PeerId || {{vpn_peer, PeerId}, Pid, worker, _Modules} <- peer_children(),
                          is_pid(Pid)]).

configured_peers() ->
    case vpn_session_config:configured_peers() of
        {ok, Peers} -> Peers;
        {error, Reason} -> erlang:error(Reason)
    end.

peer_children() ->
    try supervisor:which_children(vpn_peer_sup) of
        Children ->
            Children
    catch
        exit:{noproc, _} ->
            []
    end.
