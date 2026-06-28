%%%-------------------------------------------------------------------
%% @doc Read-only administration facade.
%%%-------------------------------------------------------------------
-module(vpn_admin).

-export([dashboard/0,
         summary/0,
         summary_view/0,
         summary_json/0,
         summary_json_pretty/0,
         certificate_view/1,
         extract_cn/1,
         overview/0,
         peer_counts/0]).

dashboard() ->
    #{status => vpn_manager:status(),
      certificates => vpn_manager:certificates()}.

summary() ->
    Status = vpn_manager:status(),
    Certificates = vpn_manager:certificates(),
    Counts = peer_counts(),
    #{counts => Counts#{certificates => length(Certificates)},
      peers => [summary_peer(PeerId, PeerStatus, Certificates)
                || {PeerId, PeerStatus} <- maps:to_list(maps:get(peers, Status, #{}))]}.

summary_view() ->
    Summary = summary(),
    #{counts => maps:get(counts, Summary, #{}),
      peers => [peer_view(Peer) || Peer <- maps:get(peers, Summary, [])]}.

summary_json() ->
    try
        iolist_to_binary(json:encode(summary_view()))
    catch
        _:Reason ->
            iolist_to_binary(
              json:encode(#{error => <<"summary_generation_failed">>,
                            reason => iolist_to_binary(io_lib:format("~p", [Reason]))}))
    end.

summary_json_pretty() ->
    summary_json().

overview() ->
    Counts = peer_counts(),
    #{configured_peers => maps:get(configured, Counts),
      running_peers => maps:get(running, Counts),
      stopped_peers => maps:get(stopped, Counts),
      certificates => length(vpn_manager:certificates())}.

peer_counts() ->
    Configured = length(vpn_manager:list_peers()),
    Running = length(vpn_manager:running_peers()),
    #{configured => Configured,
      running => Running,
      stopped => Configured - Running}.

summary_peer(PeerId, PeerStatus, Certificates) ->
    Config = maps:get(config, PeerStatus, #{}),
    Stats = maps:get(stats, PeerStatus, #{}),
    LinkStats = maps:get(link, Stats, #{}),
    Certificate = certificate_for_peer(PeerId, Certificates),
    #{id => PeerId,
      running => maps:get(running, PeerStatus, false),
      mode => maps:get(mode, Config, undefined),
      ip => maps:get(ip, Config, undefined),
      remote_peer_id => maps:get(remote_peer_id, Config, undefined),
      device_id => maps:get(device_id, Config, undefined),
      allocation_id => maps:get(allocation_id, Config, undefined),
      allocator_instance_id => maps:get(allocator_instance_id, Config, undefined),
      allocation_slot => maps:get(allocation_slot, Config, undefined),
      allocation_generation => maps:get(allocation_generation, Config, undefined),
      allocation_role => maps:get(allocation_role, Config, undefined),
      profile_id => maps:get(profile_id, Config, undefined),
      authorization_mode => maps:get(authorization_mode, Config, policy),
      authorized => maps:get(authorized, Config, false),
      authorization_reason => maps:get(authorization_reason, Config, undefined),
      crypto_failures => maps:get(crypto_failures, LinkStats, 0),
      frames_rejected => maps:get(frames_rejected, LinkStats, 0),
      replay_drops => maps:get(replay_drops, LinkStats, 0),
      duplicate_frames => maps:get(duplicate_frames, LinkStats, 0),
      stale_epoch_drops => maps:get(stale_epoch_drops, LinkStats, 0),
      previous_epoch_accepted => maps:get(previous_epoch_accepted, LinkStats, 0),
      auto_rekeys_started => maps:get(auto_rekeys_started, LinkStats, 0),
      auto_rekeys_completed => maps:get(auto_rekeys_completed, LinkStats, 0),
      auto_rekeys_failed => maps:get(auto_rekeys_failed, LinkStats, 0),
      session => maps:get(session, LinkStats, undefined),
      replay => maps:get(replay, LinkStats, undefined),
      auto_rekey => maps:get(auto_rekey, LinkStats, undefined),
      certificate => compact_certificate(Certificate)}.

certificate_for_peer(PeerId, Certificates) ->
    case [Certificate || #{peer_id := Id} = Certificate <- Certificates,
                         Id =:= PeerId] of
        [Certificate | _] ->
            Certificate;
        [] ->
            #{}
    end.

compact_certificate(Certificate) ->
    maps:with(
        [subject,
            issuer,
            trusted,
            key_match,
            not_before,
            not_after],
        Certificate).

peer_view(Peer) ->
    #{id => json_value(maps:get(id, Peer, undefined)),
      running => maps:get(running, Peer, false),
      mode => json_value(maps:get(mode, Peer, undefined)),
      ip => json_value(maps:get(ip, Peer, undefined)),
      remote_peer_id => json_value(maps:get(remote_peer_id, Peer, undefined)),
      device_id => json_value(maps:get(device_id, Peer, undefined)),
      allocation_id => json_value(maps:get(allocation_id, Peer, undefined)),
      allocator_instance_id => json_value(maps:get(allocator_instance_id,
                                                    Peer,
                                                    undefined)),
      allocation_slot => json_value(maps:get(allocation_slot, Peer, undefined)),
      allocation_generation => json_value(maps:get(allocation_generation,
                                                    Peer,
                                                    undefined)),
      allocation_role => json_value(maps:get(allocation_role, Peer, undefined)),
      profile_id => json_value(maps:get(profile_id, Peer, undefined)),
      authorization_mode => json_value(maps:get(authorization_mode, Peer, policy)),
      authorized => maps:get(authorized, Peer, false),
      authorization_reason => json_value(maps:get(authorization_reason, Peer, undefined)),
      crypto_failures => maps:get(crypto_failures, Peer, 0),
      frames_rejected => maps:get(frames_rejected, Peer, 0),
      replay_drops => maps:get(replay_drops, Peer, 0),
      duplicate_frames => maps:get(duplicate_frames, Peer, 0),
      stale_epoch_drops => maps:get(stale_epoch_drops, Peer, 0),
      previous_epoch_accepted => maps:get(previous_epoch_accepted, Peer, 0),
      auto_rekeys_started => maps:get(auto_rekeys_started, Peer, 0),
      auto_rekeys_completed => maps:get(auto_rekeys_completed, Peer, 0),
      auto_rekeys_failed => maps:get(auto_rekeys_failed, Peer, 0),
      session => session_view(maps:get(session, Peer, undefined)),
      replay => replay_view(maps:get(replay, Peer, undefined)),
      auto_rekey => auto_rekey_view(maps:get(auto_rekey, Peer, undefined)),
      certificate => certificate_view(maps:get(certificate, Peer, #{}))}.

certificate_view(Certificate) ->
    #{subject_cn => extract_cn(maps:get(subject, Certificate, undefined)),
      issuer_cn => extract_cn(maps:get(issuer, Certificate, undefined)),
      trusted => maps:get(trusted, Certificate, false),
      key_match => maps:get(key_match, Certificate, false),
      not_before => time_value(maps:get(not_before, Certificate, undefined)),
      not_after => time_value(maps:get(not_after, Certificate, undefined))}.

extract_cn({rdnSequence, RDNs}) ->
    extract_cn_from_rdns(RDNs);
extract_cn({subject, PeerId}) ->
    json_value(PeerId);
extract_cn({issuer, PeerId}) ->
    json_value(PeerId);
extract_cn(Value) ->
    json_value(Value).

extract_cn_from_rdns([[{'AttributeTypeAndValue', {2,5,4,3}, Value} | _] | _]) ->
    directory_string_value(Value);
extract_cn_from_rdns([_ | Rest]) ->
    extract_cn_from_rdns(Rest);
extract_cn_from_rdns([]) ->
    null.

directory_string_value({utf8String, Value}) ->
    json_value(Value);
directory_string_value({printableString, Value}) ->
    json_value(Value);
directory_string_value({teletexString, Value}) ->
    json_value(Value);
directory_string_value({bmpString, Value}) ->
    json_value(Value);
directory_string_value(<<12, Len:8, Value:Len/binary, _/binary>>) ->
    Value;
directory_string_value(Value) ->
    json_value(Value).

time_value({utcTime, Value}) ->
    json_value(Value);
time_value({generalTime, Value}) ->
    json_value(Value);
time_value(Value) ->
    json_value(Value).


auto_rekey_view(undefined) ->
    null;
auto_rekey_view(AutoRekey) when is_map(AutoRekey) ->
    maps:with([enabled, after_seconds, after_packets, check_interval_ms,
               failure_cooldown_ms, jitter_ms, pending, pending_reason,
               pending_remaining_ms, in_progress, last_reason,
               last_started_at, last_completed_at, last_error,
               cooldown_remaining_ms],
              AutoRekey).

replay_view(undefined) ->
    null;
replay_view(Replay) when is_map(Replay) ->
    #{window_size => maps:get(window_size, Replay, 0),
      current_epoch => maps:get(current_epoch, Replay, 0),
      current => replay_window_view(maps:get(current, Replay, undefined)),
      previous_epoch => json_value(maps:get(previous_epoch, Replay, undefined)),
      previous => replay_window_view(maps:get(previous, Replay, undefined)),
      previous_epoch_grace_ms => maps:get(previous_epoch_grace_ms, Replay, 0),
      previous_epoch_expires_in_ms =>
          json_value(maps:get(previous_epoch_expires_in_ms, Replay, undefined))}.

replay_window_view(undefined) ->
    null;
replay_window_view(Window) when is_map(Window) ->
    maps:with([size, highest, accepted, duplicates, too_old], Window).

session_view(undefined) ->
    null;
session_view(Session) when is_map(Session) ->
    maps:with([established_at,
               session_age_seconds,
               key_epoch,
               last_rekey_at,
               tx_packets_since_rekey,
               tx_bytes_since_rekey,
               rx_packets_since_rekey,
               rx_bytes_since_rekey,
               packets_since_rekey,
               bytes_since_rekey],
              Session).

json_value(undefined) ->
    null;
json_value(null) ->
    null;
json_value(Value) when is_binary(Value); is_boolean(Value); is_integer(Value); is_float(Value) ->
    Value;
json_value(Value) when is_atom(Value) ->
    atom_to_binary(Value, utf8);
json_value(Value) when is_list(Value) ->
    unicode:characters_to_binary(Value);
json_value(Value) when is_map(Value) ->
    maps:map(fun(_Key, MapValue) -> json_value(MapValue) end, Value);
json_value(_Value) ->
    null.
