%%%-------------------------------------------------------------------
%% @doc Publishes sanitized VPN runtime change notifications.
%%
%% Subscribers receive `{vpn_event, Event}` messages. Events are wake-up
%% notifications only: consumers must read the current authoritative state
%% through the normal VPN APIs instead of treating event payloads as state.
%%%-------------------------------------------------------------------
-module(vpn_event_bus).

-behaviour(gen_server).

-export([start_link/0,
         subscribe/1,
         unsubscribe/1,
         publish/1,
         status/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(EVENT_SCHEMA_VERSION, 1).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

subscribe(SubscriberPid) when is_pid(SubscriberPid) ->
    call_server({subscribe, SubscriberPid});
subscribe(_SubscriberPid) ->
    {error, invalid_subscriber}.

unsubscribe(SubscriberPid) when is_pid(SubscriberPid) ->
    call_server({unsubscribe, SubscriberPid});
unsubscribe(_SubscriberPid) ->
    {error, invalid_subscriber}.

publish(Event) when is_map(Event) ->
    case whereis(?SERVER) of
        undefined -> {error, not_started};
        _Pid ->
            gen_server:cast(?SERVER, {publish, Event}),
            ok
    end;
publish(_Event) ->
    {error, invalid_event}.

status() ->
    call_server(status).

call_server(Request) ->
    case whereis(?SERVER) of
        undefined -> {error, not_started};
        _Pid -> gen_server:call(?SERVER, Request)
    end.

init([]) ->
    StreamId = {node(), erlang:unique_integer([positive, monotonic])},
    {ok, #{stream_id => StreamId,
           sequence => 0,
           published => 0,
           subscribers => #{},
           monitors => #{},
           last_event => undefined}}.

handle_call({subscribe, SubscriberPid}, _From, State0) ->
    Subscribers0 = maps:get(subscribers, State0),
    case maps:find(SubscriberPid, Subscribers0) of
        {ok, _MonitorRef} ->
            {reply, subscription_reply(State0), State0};
        error ->
            MonitorRef = erlang:monitor(process, SubscriberPid),
            State1 = State0#{
                       subscribers => Subscribers0#{SubscriberPid => MonitorRef},
                       monitors => (maps:get(monitors, State0))#{MonitorRef => SubscriberPid}},
            {reply, subscription_reply(State1), State1}
    end;
handle_call({unsubscribe, SubscriberPid}, _From, State0) ->
    {reply, ok, remove_subscriber(SubscriberPid, State0)};
handle_call(status, _From, State) ->
    {reply, public_status(State), State};
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_operation}, State}.

handle_cast({publish, Event0}, State0) ->
    Sequence = maps:get(sequence, State0) + 1,
    Event = maps:merge(
              Event0,
              #{schema_version => ?EVENT_SCHEMA_VERSION,
                stream_id => maps:get(stream_id, State0),
                sequence => Sequence,
                emitted_at => erlang:system_time(millisecond)}),
    maps:foreach(
      fun(SubscriberPid, _MonitorRef) ->
              SubscriberPid ! {vpn_event, Event}
      end,
      maps:get(subscribers, State0)),
    State1 = State0#{sequence => Sequence,
                     published => maps:get(published, State0) + 1,
                     last_event => Event},
    {noreply, State1};
handle_cast(_Message, State) ->
    {noreply, State}.

handle_info({'DOWN', MonitorRef, process, _SubscriberPid, _Reason}, State0) ->
    Monitors0 = maps:get(monitors, State0),
    case maps:take(MonitorRef, Monitors0) of
        {SubscriberPid, Monitors1} ->
            Subscribers1 = maps:remove(SubscriberPid,
                                       maps:get(subscribers, State0)),
            {noreply, State0#{subscribers => Subscribers1,
                              monitors => Monitors1}};
        error ->
            {noreply, State0}
    end;
handle_info(_Message, State) ->
    {noreply, State}.

subscription_reply(State) ->
    {ok, #{schema_version => ?EVENT_SCHEMA_VERSION,
           stream_id => maps:get(stream_id, State),
           sequence => maps:get(sequence, State)}}.

remove_subscriber(SubscriberPid, State0) ->
    Subscribers0 = maps:get(subscribers, State0),
    case maps:take(SubscriberPid, Subscribers0) of
        {MonitorRef, Subscribers1} ->
            _ = erlang:demonitor(MonitorRef, [flush]),
            State0#{subscribers => Subscribers1,
                    monitors => maps:remove(MonitorRef,
                                            maps:get(monitors, State0))};
        error ->
            State0
    end.

public_status(State) ->
    #{schema_version => ?EVENT_SCHEMA_VERSION,
      stream_id => maps:get(stream_id, State),
      sequence => maps:get(sequence, State),
      published => maps:get(published, State),
      subscriber_count => map_size(maps:get(subscribers, State)),
      last_event => maps:get(last_event, State)}.
