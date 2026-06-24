%%%-------------------------------------------------------------------
%% @doc Process-independent in-memory projection backend for EUnit fixtures.
%%%-------------------------------------------------------------------
-module(vpn_projection_test_store).

-behaviour(vpn_projection_store).

-export([load/0,
         commit/2,
         reset/0,
         fail_next_commit/1]).

-define(STATE_KEY, {?MODULE, state}).
-define(FAIL_KEY, {?MODULE, fail_next_commit}).

load() ->
    case persistent_term:get(?STATE_KEY, undefined) of
        undefined -> not_found;
        {Version, Envelope} -> {ok, Version, Envelope}
    end.

commit(ExpectedVersion, Envelope)
  when is_integer(ExpectedVersion), ExpectedVersion >= 0, is_map(Envelope) ->
    case persistent_term:get(?FAIL_KEY, undefined) of
        undefined ->
            commit_current(ExpectedVersion, Envelope);
        Reason ->
            persistent_term:erase(?FAIL_KEY),
            {error, Reason}
    end;
commit(_ExpectedVersion, _Envelope) ->
    {error, invalid_commit_arguments}.

reset() ->
    persistent_term:erase(?STATE_KEY),
    persistent_term:erase(?FAIL_KEY),
    ok.

fail_next_commit(Reason) ->
    persistent_term:put(?FAIL_KEY, Reason),
    ok.

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
