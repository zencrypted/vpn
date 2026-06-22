%%%-------------------------------------------------------------------
%% @doc VPN control-plane handshake state machine.
%%
%% development_control proves liveness and peer-id agreement only.
%% certificate_control additionally exchanges certificates, validates each
%% remote certificate against an explicitly configured trust anchor, and
%% verifies a transcript signature proving possession of the private key.
%%%-------------------------------------------------------------------
-module(vpn_handshake).

-export([new/3, begin_handshake/1, handle_frame/2, retry/1,
         established/1, status/1, info/1]).

-define(ID_SIZE, 16).

new(LocalPeerId, RemotePeerId, Options) when is_map(Options) ->
    Mode = maps:get(mode, Options, disabled),
    Base = #{mode => Mode,
             status => idle,
             local_peer_id => normalize_peer_id(LocalPeerId),
             remote_peer_id => normalize_peer_id(RemotePeerId),
             session_id => crypto:strong_rand_bytes(?ID_SIZE),
             nonce => crypto:strong_rand_bytes(?ID_SIZE),
             remote_session_id => undefined,
             remote_nonce => undefined,
             remote_authenticated => false,
             remote_certificate_fingerprint => undefined,
             pending_ack => undefined,
             retries => 0,
             max_retries => maps:get(max_retries, Options, 5),
             retry_interval => maps:get(retry_interval, Options, 1000)},
    maps:merge(Base, authentication_options(Mode, Options)).

begin_handshake(State = #{mode := disabled}) ->
    {established, State#{status := established}};
begin_handshake(State) ->
    {send, hello(State), State#{status := waiting_peer, retries := 1}}.

handle_frame(Packet, State) ->
    case vpn_handshake_frame:decode(Packet) of
        {ok, #{type := hello} = Frame} -> handle_hello(Frame, State);
        {ok, #{type := proof} = Frame} -> handle_proof(Frame, State);
        {ok, #{type := ack} = Frame} -> handle_ack(Frame, State);
        {error, _} = Error -> {reject, Error, State}
    end.

retry(State = #{status := established}) ->
    {established, State};
retry(State = #{retries := Retries, max_retries := Max}) when Retries >= Max ->
    {failed, timeout, State#{status := failed}};
retry(State) ->
    Retries = maps:get(retries, State) + 1,
    {send, retry_frame(State), State#{retries := Retries}}.

established(#{status := established}) -> true;
established(_) -> false.

status(State) -> maps:get(status, State).

info(State) ->
    maps:with([mode, status, retries, max_retries, retry_interval,
               session_id, remote_session_id, remote_authenticated,
               remote_certificate_fingerprint], State).

handle_hello(#{peer_id := PeerId, session_id := RemoteSession, nonce := RemoteNonce}, State) ->
    case validate_peer(PeerId, State) of
        ok ->
            State1 = State#{remote_session_id := RemoteSession,
                            remote_nonce := RemoteNonce},
            case maps:get(mode, State1) of
                certificate_control ->
                    case proof(State1) of
                        {ok, Proof} ->
                            {send, Proof, State1#{status := preserve_established(State1,
                                                                               waiting_proof_ack)}};
                        {error, Reason} -> {reject, {error, Reason}, State1#{status := failed}}
                    end;
                _ ->
                    {send, ack(State1), State1}
            end;
        {error, _} = Error ->
            {reject, Error, State}
    end.

handle_proof(#{peer_id := PeerId,
               session_id := RemoteSession,
               ack_for := AckFor,
               nonce := RemoteNonce,
               certificate_der := CertificateDer,
               signature := Signature},
             State = #{mode := certificate_control}) ->
    case {validate_peer(PeerId, State), AckFor =:= maps:get(session_id, State)} of
        {ok, true} ->
            State1 = State#{remote_session_id := RemoteSession,
                            remote_nonce := RemoteNonce},
            case verify_remote_proof(CertificateDer, Signature, State1) of
                {ok, Fingerprint} ->
                    Authenticated = State1#{remote_authenticated := true,
                                            remote_certificate_fingerprint := Fingerprint},
                    complete_proof(Authenticated);
                {error, Reason} ->
                    {reject, {error, Reason}, State1#{status := failed}}
            end;
        {{error, _} = Error, _} -> {reject, Error, State};
        {ok, false} -> {reject, {error, handshake_session_mismatch}, State}
    end;
handle_proof(_Frame, State) ->
    {reject, {error, unexpected_certificate_proof}, State}.

handle_ack(#{peer_id := PeerId, ack_for := AckFor, session_id := RemoteSession}, State) ->
    case {validate_peer(PeerId, State), AckFor =:= maps:get(session_id, State),
          authentication_complete(State)} of
        {ok, true, true} ->
            {established, State#{status := established,
                                 remote_session_id := RemoteSession}};
        {{error, _} = Error, _, _} -> {reject, Error, State};
        {ok, false, _} -> {reject, {error, handshake_session_mismatch}, State};
        {ok, true, false} ->
            {defer, State#{pending_ack := #{peer_id => PeerId,
                                           ack_for => AckFor,
                                           session_id => RemoteSession}}}
    end.

complete_proof(State = #{pending_ack := Pending}) when is_map(Pending) ->
    RemoteSession = maps:get(session_id, Pending),
    Established = State#{status := established,
                         remote_session_id := RemoteSession,
                         pending_ack := undefined},
    {send_established, ack(Established), Established};
complete_proof(State) ->
    {send, ack(State),
     State#{status := preserve_established(State, waiting_ack)}}.

proof(State) ->
    CertificateDer = maps:get(local_certificate_der, State),
    Data = proof_data(State, CertificateDer),
    case vpn_handshake_auth:sign(Data, maps:get(local_private_key_path, State)) of
        {ok, Signature} ->
            {ok, vpn_handshake_frame:encode_proof(
                   maps:get(local_peer_id, State),
                   maps:get(session_id, State),
                   maps:get(remote_session_id, State),
                   maps:get(nonce, State),
                   CertificateDer,
                   Signature)};
        {error, Reason} -> {error, {certificate_proof_sign_failed, Reason}}
    end.

verify_remote_proof(CertificateDer, Signature, State) ->
    Data = remote_proof_data(State, CertificateDer),
    case vpn_handshake_auth:verify(CertificateDer,
                                   maps:get(remote_ca_certificate_path, State),
                                   maps:get(remote_peer_id, State),
                                   Data,
                                   Signature) of
        ok -> {ok, hex(crypto:hash(sha256, CertificateDer))};
        {error, Reason} -> {error, {certificate_proof_verification_failed, Reason}}
    end.

proof_data(State, CertificateDer) ->
    vpn_handshake_auth:proof_data(
      maps:get(local_peer_id, State), maps:get(remote_peer_id, State),
      maps:get(session_id, State), maps:get(remote_session_id, State),
      maps:get(nonce, State), maps:get(remote_nonce, State), CertificateDer).

remote_proof_data(State, CertificateDer) ->
    vpn_handshake_auth:proof_data(
      maps:get(remote_peer_id, State), maps:get(local_peer_id, State),
      maps:get(remote_session_id, State), maps:get(session_id, State),
      maps:get(remote_nonce, State), maps:get(nonce, State), CertificateDer).

hello(State) ->
    vpn_handshake_frame:encode_hello(maps:get(local_peer_id, State),
                                     maps:get(session_id, State),
                                     maps:get(nonce, State)).

ack(State) ->
    vpn_handshake_frame:encode_ack(maps:get(local_peer_id, State),
                                   maps:get(session_id, State),
                                   maps:get(remote_session_id, State),
                                   maps:get(nonce, State)).

retry_frame(State = #{mode := certificate_control,
                      remote_session_id := RemoteSession}) when is_binary(RemoteSession) ->
    case proof(State) of
        {ok, Packet} -> Packet;
        {error, _} -> hello(State)
    end;
retry_frame(State) -> hello(State).

preserve_established(#{status := established}, _Next) -> established;
preserve_established(_State, Next) -> Next.

authentication_complete(#{mode := certificate_control,
                          remote_authenticated := true}) -> true;
authentication_complete(#{mode := certificate_control}) -> false;
authentication_complete(_) -> true.

authentication_options(certificate_control, Options) ->
    Required = [local_certificate_pem, local_private_key_path, remote_ca_certificate_path],
    case missing_option(Options, Required) of
        none ->
            case vpn_handshake_auth:certificate_der(maps:get(local_certificate_pem, Options)) of
                {ok, Der} ->
                    #{local_certificate_der => Der,
                      local_private_key_path => maps:get(local_private_key_path, Options),
                      remote_ca_certificate_path => maps:get(remote_ca_certificate_path, Options)};
                {error, Reason} -> erlang:error({invalid_handshake_certificate, Reason})
            end;
        {missing, Key} -> erlang:error({missing_handshake_option, Key})
    end;
authentication_options(_Mode, _Options) -> #{}.

missing_option(_Options, []) -> none;
missing_option(Options, [Key | Rest]) ->
    case maps:is_key(Key, Options) of
        true -> missing_option(Options, Rest);
        false -> {missing, Key}
    end.

validate_peer(PeerId, State) ->
    case normalize_peer_id(PeerId) =:= maps:get(remote_peer_id, State) of
        true -> ok;
        false -> {error, handshake_peer_id_mismatch}
    end.

normalize_peer_id(PeerId) when is_atom(PeerId) -> atom_to_binary(PeerId, utf8);
normalize_peer_id(PeerId) when is_binary(PeerId) -> PeerId.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).
