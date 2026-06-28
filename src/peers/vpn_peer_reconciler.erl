%%%-------------------------------------------------------------------
%% @doc Applies runtime peer registry mutations to the supervised peer set.
%%
%% Registry calls remain fast and non-blocking: mutations are reported here
%% through casts, then serialized into start/stop/restart operations.
%%%-------------------------------------------------------------------
-module(vpn_peer_reconciler).

-behaviour(gen_server).

-export([start_link/0, notify/1, status/0, reconcile_now/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

notify(Event) ->
    case whereis(?SERVER) of
        undefined -> ok;
        _Pid -> gen_server:cast(?SERVER, {registry_event, Event})
    end.

status() ->
    gen_server:call(?SERVER, status).

reconcile_now() ->
    gen_server:call(?SERVER, reconcile_now, infinity).

init([]) ->
    {ok, #{events_received => 0,
           reconciliations => 0,
           failures => 0,
           last_event => undefined,
           last_result => undefined}}.

handle_call(status, _From, State) ->
    {reply, State, State};
handle_call(reconcile_now, _From, State) ->
    Result = vpn_manager:reload_config(),
    _ = publish_runtime_reconciled(manual_reload, Result),
    {reply, Result, record_result(manual_reload, Result, State)};
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_operation}, State}.

handle_cast({registry_event, Event}, State0) ->
    Result = reconcile_event(Event),
    _ = publish_runtime_reconciled(Event, Result),
    State1 = State0#{events_received => maps:get(events_received, State0) + 1},
    {noreply, record_result(Event, Result, State1)};
handle_cast(_Message, State) ->
    {noreply, State}.

handle_info(_Message, State) ->
    {noreply, State}.

reconcile_event(#{action := put,
                  peer_id := PeerId,
                  restart_required := RestartRequired}) ->
    reconcile_put(PeerId, RestartRequired);
reconcile_event(#{action := put, peer_id := PeerId}) ->
    reconcile_put(PeerId, true);
reconcile_event(#{action := put_many, peer_changes := PeerChanges}) ->
    reconcile_many(PeerChanges);
reconcile_event(#{action := put_many, peer_ids := PeerIds}) ->
    reconcile_many([#{peer_id => PeerId, restart_required => true}
                    || PeerId <- PeerIds]);
reconcile_event(_Event) ->
    vpn_manager:reload_config().


reconcile_many(PeerChanges) ->
    lists:foldl(fun(#{peer_id := PeerId,
                      restart_required := RestartRequired}, Acc) ->
                        merge_results(Acc,
                                      reconcile_put(PeerId, RestartRequired))
                end,
                empty_result(),
                PeerChanges).

empty_result() ->
    #{started => [], stopped => [], failed => [], unchanged => []}.

merge_results(Left, Right) ->
    maps:from_list([{Key,
                     maps:get(Key, Left, []) ++ maps:get(Key, Right, [])}
                    || Key <- [started, stopped, failed, unchanged]]).

reconcile_put(PeerId, RestartRequired) ->
    case vpn_peer_registry:get(PeerId) of
        {ok, #{enabled := false}} ->
            ensure_stopped(PeerId);
        {ok, #{enabled := true}} ->
            reconcile_enabled(PeerId, RestartRequired);
        {error, not_found} ->
            ensure_stopped(PeerId)
    end.

reconcile_enabled(PeerId, false) ->
    case vpn_manager:peer_running(PeerId) of
        true ->
            #{started => [], stopped => [], failed => [], unchanged => [PeerId]};
        false ->
            normalize_start(PeerId, vpn_manager:start_peer(PeerId))
    end;
reconcile_enabled(PeerId, true) ->
    restart_or_start(PeerId).

restart_or_start(PeerId) ->
    StopResult = case vpn_manager:peer_running(PeerId) of
                     true -> vpn_manager:stop_peer(PeerId);
                     false -> ok
                 end,
    case StopResult of
        ok ->
            normalize_start(PeerId, vpn_manager:start_peer(PeerId));
        {error, Reason} ->
            #{started => [], stopped => [], failed => [{PeerId, Reason}], unchanged => []}
    end.

ensure_stopped(PeerId) ->
    case vpn_manager:peer_running(PeerId) of
        true ->
            case vpn_manager:stop_peer(PeerId) of
                ok -> #{started => [], stopped => [PeerId], failed => [], unchanged => []};
                {error, Reason} ->
                    #{started => [], stopped => [], failed => [{PeerId, Reason}], unchanged => []}
            end;
        false ->
            #{started => [], stopped => [], failed => [], unchanged => []}
    end.

normalize_start(PeerId, {ok, _Pid}) ->
    #{started => [PeerId], stopped => [], failed => [], unchanged => []};
normalize_start(PeerId, {error, Reason}) ->
    #{started => [], stopped => [], failed => [{PeerId, Reason}], unchanged => []}.

record_result(Event, Result, State) ->
    FailureCount = case maps:get(failed, Result, []) of
                       [] -> maps:get(failures, State);
                       _ -> maps:get(failures, State) + 1
                   end,
    State#{reconciliations => maps:get(reconciliations, State) + 1,
           failures => FailureCount,
           last_event => Event,
           last_result => Result}.

publish_runtime_reconciled(Cause, Result) ->
    vpn_event_bus:publish(
      #{type => runtime_reconciled,
        cause => safe_cause(Cause),
        result => safe_result(Result)}).

safe_cause(manual_reload) ->
    #{action => manual_reload};
safe_cause(Event) when is_map(Event) ->
    Base = maps:with([action,
                      peer_id,
                      peer_ids,
                      enabled,
                      restart_required],
                     Event),
    case maps:find(peer_changes, Event) of
        {ok, PeerChanges} when is_list(PeerChanges) ->
            Base#{peer_changes =>
                      [maps:with([peer_id, restart_required], PeerChange)
                       || PeerChange <- PeerChanges,
                          is_map(PeerChange)]};
        _ ->
            Base
    end;
safe_cause(_Cause) ->
    #{action => unknown}.

safe_result(Result) when is_map(Result) ->
    Started = maps:get(started, Result, []),
    Stopped = maps:get(stopped, Result, []),
    Failed = maps:get(failed, Result, []),
    Unchanged = maps:get(unchanged, Result, []),
    PeerIds = lists:usort(peer_ids(Started) ++
                          peer_ids(Stopped) ++
                          peer_ids(Failed) ++
                          peer_ids(Unchanged)),
    #{outcome => result_outcome(Failed),
      started => length(Started),
      stopped => length(Stopped),
      failed => length(Failed),
      unchanged => length(Unchanged),
      peer_ids => PeerIds};
safe_result(_Result) ->
    #{outcome => invalid_result,
      started => 0,
      stopped => 0,
      failed => 0,
      unchanged => 0,
      peer_ids => []}.

result_outcome([]) -> ok;
result_outcome(_Failed) -> partial_failure.

peer_ids(Values) when is_list(Values) ->
    [peer_id(Value) || Value <- Values, peer_id(Value) =/= undefined];
peer_ids(_Values) ->
    [].

peer_id({PeerId, _Reason}) -> PeerId;
peer_id(PeerId) when is_atom(PeerId); is_binary(PeerId) -> PeerId;
peer_id(_Value) -> undefined.
