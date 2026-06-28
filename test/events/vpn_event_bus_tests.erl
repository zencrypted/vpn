-module(vpn_event_bus_tests).

-include_lib("eunit/include/eunit.hrl").

event_bus_subscription_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Pid) ->
             [?_test(begin
                          {ok, Initial} = vpn_event_bus:subscribe(self()),
                          ?assertEqual(0, maps:get(sequence, Initial)),
                          ?assertEqual(1,
                                       maps:get(subscriber_count,
                                                vpn_event_bus:status())),

                          %% Re-subscribing is idempotent and must not create
                          %% duplicate delivery or duplicate process monitors.
                          {ok, Initial} = vpn_event_bus:subscribe(self()),
                          ok = vpn_event_bus:publish(#{type => test_event,
                                                       value => one}),
                          Event1 = receive_event(),
                          ?assertMatch(#{schema_version := 1,
                                         type := test_event,
                                         value := one,
                                         sequence := 1},
                                       Event1),
                          assert_no_event(),

                          ok = vpn_event_bus:publish(#{type => test_event,
                                                       value => two}),
                          Event2 = receive_event(),
                          ?assertEqual(2, maps:get(sequence, Event2)),
                          ?assertEqual(maps:get(stream_id, Event1),
                                       maps:get(stream_id, Event2)),

                          ok = vpn_event_bus:unsubscribe(self()),
                          ?assertEqual(0,
                                       maps:get(subscriber_count,
                                                vpn_event_bus:status())),
                          ok = vpn_event_bus:publish(#{type => ignored}),
                          assert_no_event()
                      end)]
     end}.

dead_subscriber_is_removed_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_Pid) ->
             [?_test(begin
                          Subscriber = spawn(fun subscriber_loop/0),
                          {ok, _} = vpn_event_bus:subscribe(Subscriber),
                          ?assertEqual(1,
                                       maps:get(subscriber_count,
                                                vpn_event_bus:status())),
                          exit(Subscriber, kill),
                          ?assert(wait_until(
                                    fun() ->
                                            maps:get(subscriber_count,
                                                     vpn_event_bus:status()) =:= 0
                                    end,
                                    50))
                      end)]
     end}.

setup() ->
    stop_registered(vpn_event_bus),
    {ok, Pid} = vpn_event_bus:start_link(),
    Pid.

cleanup(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            exit(Pid, shutdown),
            wait_until_stopped(Pid, 20);
        false -> ok
    end.

receive_event() ->
    receive
        {vpn_event, Event} -> Event
    after 1000 ->
        error(vpn_event_timeout)
    end.

assert_no_event() ->
    receive
        {vpn_event, Event} -> error({unexpected_vpn_event, Event})
    after 50 ->
        ok
    end.

subscriber_loop() ->
    receive
        stop -> ok
    end.

stop_registered(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            unlink(Pid),
            exit(Pid, shutdown),
            wait_until_stopped(Pid, 20)
    end.

wait_until_stopped(_Pid, 0) -> ok;
wait_until_stopped(Pid, Attempts) ->
    case is_process_alive(Pid) of
        false -> ok;
        true -> timer:sleep(10), wait_until_stopped(Pid, Attempts - 1)
    end.

wait_until(_Fun, 0) -> false;
wait_until(Fun, Attempts) ->
    case Fun() of
        true -> true;
        false -> timer:sleep(10), wait_until(Fun, Attempts - 1)
    end.
