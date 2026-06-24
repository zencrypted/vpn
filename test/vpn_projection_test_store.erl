%%%-------------------------------------------------------------------
%% @doc Process-independent in-memory projection backend for EUnit fixtures.
%%%-------------------------------------------------------------------
-module(vpn_projection_test_store).

-behaviour(vpn_projection_store).

-export([load/0,
         commit/2,
         reset/0,
         fail_next_commit/1,
         fail_after_commits/2]).

-define(STATE_KEY, {?MODULE, state}).
-define(FAIL_KEY, {?MODULE, fail_next_commit}).
-define(FAIL_AFTER_KEY, {?MODULE, fail_after_commits}).

load() ->
    case persistent_term:get(?STATE_KEY, undefined) of
        undefined -> not_found;
        {Version, Envelope} -> {ok, Version, Envelope}
    end.

commit(ExpectedVersion, Envelope)
  when is_integer(ExpectedVersion), ExpectedVersion >= 0, is_map(Envelope) ->
    case persistent_term:get(?FAIL_KEY, undefined) of
        undefined ->
            commit_with_delayed_failure(ExpectedVersion, Envelope);
        Reason ->
            persistent_term:erase(?FAIL_KEY),
            {error, Reason}
    end;
commit(_ExpectedVersion, _Envelope) ->
    {error, invalid_commit_arguments}.

reset() ->
    persistent_term:erase(?STATE_KEY),
    persistent_term:erase(?FAIL_KEY),
    persistent_term:erase(?FAIL_AFTER_KEY),
    ok.

fail_next_commit(Reason) ->
    persistent_term:put(?FAIL_KEY, Reason),
    ok.

fail_after_commits(Count, Reason)
  when is_integer(Count), Count >= 0 ->
    persistent_term:put(?FAIL_AFTER_KEY, {Count, Reason}),
    ok.

commit_with_delayed_failure(ExpectedVersion, Envelope) ->
    case persistent_term:get(?FAIL_AFTER_KEY, undefined) of
        undefined ->
            commit_current(ExpectedVersion, Envelope);
        {0, Reason} ->
            persistent_term:erase(?FAIL_AFTER_KEY),
            {error, Reason};
        {Remaining, Reason} when Remaining > 0 ->
            persistent_term:put(?FAIL_AFTER_KEY,
                                {Remaining - 1, Reason}),
            commit_current(ExpectedVersion, Envelope)
    end.

commit_current(0, Envelope) ->
    case persistent_term:get(?STATE_KEY, undefined) of
        undefined -> store(Envelope);
        _ -> {error, conflict}
    end;
commit_current(ExpectedVersion, Envelope) ->
    case persistent_term:get(?STATE_KEY, undefined) of
        {ExpectedVersion, _CurrentEnvelope} -> store(Envelope);
        _ -> {error, conflict}
    end.

store(#{projection_version := NewVersion} = Envelope)
  when is_integer(NewVersion), NewVersion > 0 ->
    persistent_term:put(?STATE_KEY, {NewVersion, Envelope}),
    {ok, NewVersion};
store(_Envelope) ->
    {error, invalid_projection_envelope}.
