%%%-------------------------------------------------------------------
%% @doc Development handshake state machine.
%%
%% This establishes control-plane liveness and peer-id agreement before the
%% existing PSK dataplane is enabled. It is deliberately not authentication:
%% certificate exchange, transcript signatures and ECDH are the next stages.
%%%-------------------------------------------------------------------
-module(vpn_handshake).

-export([new/3, begin_handshake/1, handle_frame/2, retry/1,
         established/1, status/1, info/1]).

-define(ID_SIZE, 16).

new(LocalPeerId, RemotePeerId, Options) when is_map(Options) ->
    #{mode => maps:get(mode, Options, disabled),
      status => idle,
      local_peer_id => normalize_peer_id(LocalPeerId),
      remote_peer_id => normalize_peer_id(RemotePeerId),
      session_id => crypto:strong_rand_bytes(?ID_SIZE),
      nonce => crypto:strong_rand_bytes(?ID_SIZE),
      remote_session_id => undefined,
      retries => 0,
      max_retries => maps:get(max_retries, Options, 5),
      retry_interval => maps:get(retry_interval, Options, 1000)}.

begin_handshake(State = #{mode := disabled}) ->
    {established, State#{status := established}};
begin_handshake(State) ->
    {send, hello(State), State#{status := waiting_ack, retries := 1}}.

handle_frame(Packet, State) ->
    case vpn_handshake_frame:decode(Packet) of
        {ok, #{type := hello, peer_id := PeerId, session_id := RemoteSession}} ->
            case validate_peer(PeerId, State) of
                ok ->
                    Ack = vpn_handshake_frame:encode_ack(
                            maps:get(local_peer_id, State),
                            maps:get(session_id, State),
                            RemoteSession,
                            maps:get(nonce, State)),
                    {send, Ack, State#{remote_session_id := RemoteSession}};
                {error, _} = Error ->
                    {reject, Error, State}
            end;
        {ok, #{type := ack, peer_id := PeerId, ack_for := AckFor,
               session_id := RemoteSession}} ->
            case {validate_peer(PeerId, State), AckFor =:= maps:get(session_id, State)} of
                {ok, true} ->
                    {established, State#{status := established,
                                         remote_session_id := RemoteSession}};
                {{error, _} = Error, _} ->
                    {reject, Error, State};
                {ok, false} ->
                    {reject, {error, handshake_session_mismatch}, State}
            end;
        {error, _} = Error ->
            {reject, Error, State}
    end.

retry(State = #{status := established}) ->
    {established, State};
retry(State = #{retries := Retries, max_retries := Max}) when Retries >= Max ->
    {failed, timeout, State#{status := failed}};
retry(State) ->
    Retries = maps:get(retries, State) + 1,
    {send, hello(State), State#{status := waiting_ack, retries := Retries}}.

established(#{status := established}) -> true;
established(_) -> false.

status(State) -> maps:get(status, State).

info(State) ->
    maps:with([mode, status, retries, max_retries, retry_interval,
               session_id, remote_session_id], State).

hello(State) ->
    vpn_handshake_frame:encode_hello(maps:get(local_peer_id, State),
                                     maps:get(session_id, State),
                                     maps:get(nonce, State)).

validate_peer(PeerId, State) ->
    case normalize_peer_id(PeerId) =:= maps:get(remote_peer_id, State) of
        true -> ok;
        false -> {error, handshake_peer_id_mismatch}
    end.

normalize_peer_id(PeerId) when is_atom(PeerId) -> atom_to_binary(PeerId, utf8);
normalize_peer_id(PeerId) when is_binary(PeerId) -> PeerId.
