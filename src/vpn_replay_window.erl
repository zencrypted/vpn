%%%-------------------------------------------------------------------
%% @doc Sliding replay window for authenticated VPN data frames.
%%
%% The window tracks sequence numbers independently for each key epoch.
%% It accepts limited reordering, rejects duplicates, and rejects packets
%% that have fallen behind the configured window.
%%%-------------------------------------------------------------------
-module(vpn_replay_window).

-export([new/0, new/1, check/2, info/1]).

-define(DEFAULT_SIZE, 64).

new() ->
    new(?DEFAULT_SIZE).

new(Size) when is_integer(Size), Size > 0, Size =< 4096 ->
    #{size => Size,
      highest => -1,
      bitmap => 0,
      accepted => 0,
      duplicates => 0,
      too_old => 0}.

check(Seq, State = #{size := Size, highest := Highest, bitmap := Bitmap})
  when is_integer(Seq), Seq >= 0 ->
    case Seq > Highest of
        true ->
            Delta = Seq - Highest,
            Shifted = case Delta >= Size of
                          true -> 0;
                          false -> (Bitmap bsl Delta) band mask(Size)
                      end,
            {ok, State#{highest := Seq,
                        bitmap := Shifted bor 1,
                        accepted := maps:get(accepted, State) + 1}};
        false ->
            Offset = Highest - Seq,
            check_within_window(Offset, State)
    end.

info(State) ->
    maps:without([bitmap], State).

check_within_window(Offset, State = #{size := Size}) when Offset >= Size ->
    {error, too_old, State#{too_old := maps:get(too_old, State) + 1}};
check_within_window(Offset, State = #{bitmap := Bitmap}) ->
    Bit = 1 bsl Offset,
    case Bitmap band Bit of
        0 ->
            {ok, State#{bitmap := Bitmap bor Bit,
                        accepted := maps:get(accepted, State) + 1}};
        _ ->
            {error, duplicate,
             State#{duplicates := maps:get(duplicates, State) + 1}}
    end.

mask(Size) ->
    (1 bsl Size) - 1.
