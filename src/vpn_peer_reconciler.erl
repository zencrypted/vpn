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
    {reply, Result, record_result(manual_reload, Result, State)};
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_operation}, State}.

handle_cast({registry_event, Event}, State0) ->
    Result = reconcile_event(Event),
    State1 = State0#{events_received => maps:get(events_received, State0) + 1},
    {noreply, record_result(Event, Result, State1)};
handle_cast(_Message, State) ->
    {noreply, State}.

handle_info(_Message, State) ->
    {noreply, State}.

reconcile_event(#{action := put, peer_id := PeerId}) ->
    reconcile_put(PeerId);
reconcile_event(#{action := put_many, peer_ids := PeerIds}) ->
    reconcile_many(PeerIds);
reconcile_event(_Event) ->
    vpn_manager:reload_config().


reconcile_many(PeerIds) ->
    lists:foldl(fun(PeerId, Acc) ->
                        merge_results(Acc, reconcile_put(PeerId))
                end,
                empty_result(),
                PeerIds).

empty_result() ->
    #{started => [], stopped => [], failed => [], unchanged => []}.

merge_results(Left, Right) ->
    maps:from_list([{Key,
                     maps:get(Key, Left, []) ++ maps:get(Key, Right, [])}
                    || Key <- [started, stopped, failed, unchanged]]).

reconcile_put(PeerId) ->
    case vpn_peer_registry:get(PeerId) of
        {ok, #{enabled := false}} ->
            ensure_stopped(PeerId);
        {ok, #{enabled := true}} ->
            restart_or_start(PeerId);
        {error, not_found} ->
            ensure_stopped(PeerId)
    end.

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
