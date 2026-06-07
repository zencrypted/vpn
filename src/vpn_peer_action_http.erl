%%%-------------------------------------------------------------------
%% @doc Cowboy handler for dashboard peer start/stop actions.
%%%-------------------------------------------------------------------
-module(vpn_peer_action_http).

-export([init/2]).

init(Req0, State) ->
    case cowboy_req:method(Req0) of
        <<"POST">> ->
            PeerIdBin = cowboy_req:binding(id, Req0),
            Action = maps:get(action, State),
            run_action(Action, PeerIdBin),
            redirect(Req0, State);
        _Other ->
            Req = cowboy_req:reply(
                405,
                #{<<"allow">> => <<"POST">>},
                Req0),
            {ok, Req, State}
    end.

run_action(Action, PeerIdBin) ->
    Result =
        case find_peer_id(PeerIdBin) of
            {ok, PeerId} ->
                apply_action(Action, PeerId);
            {error, not_found} ->
                {error, not_found}
        end,
    log_result(Action, PeerIdBin, Result),
    ok.

apply_action(start, PeerId) ->
    vpn_manager:start_peer(PeerId);
apply_action(stop, PeerId) ->
    vpn_manager:stop_peer(PeerId).

find_peer_id(PeerIdBin) ->
    case [PeerId || PeerId <- vpn_manager:list_peers(),
                    peer_id_binary(PeerId) =:= PeerIdBin] of
        [PeerId | _] ->
            {ok, PeerId};
        [] ->
            {error, not_found}
    end.

peer_id_binary(PeerId) when is_binary(PeerId) ->
    PeerId;
peer_id_binary(PeerId) when is_atom(PeerId) ->
    atom_to_binary(PeerId, utf8).

log_result(_Action, _PeerIdBin, ok) ->
    ok;
log_result(_Action, _PeerIdBin, {ok, _Pid}) ->
    ok;
log_result(Action, PeerIdBin, {error, Reason}) ->
    logger:warning("vpn dashboard peer action failed action=~p peer=~s reason=~p",
                   [Action, PeerIdBin, Reason]).

redirect(Req0, State) ->
    Req = cowboy_req:reply(
        303,
        #{<<"location">> => <<"/admin">>},
        Req0),
    {ok, Req, State}.
