%%%-------------------------------------------------------------------
%% @doc Read-only administration facade.
%%%-------------------------------------------------------------------
-module(vpn_admin).

-export([dashboard/0,
         summary/0,
         summary_view/0,
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
      crypto_failures => maps:get(crypto_failures, LinkStats, 0),
      frames_rejected => maps:get(frames_rejected, LinkStats, 0),
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
    maps:with([subject, issuer, trusted, key_match, not_after], Certificate).

peer_view(Peer) ->
    #{id => json_value(maps:get(id, Peer, undefined)),
      running => maps:get(running, Peer, false),
      mode => json_value(maps:get(mode, Peer, undefined)),
      ip => json_value(maps:get(ip, Peer, undefined)),
      remote_peer_id => json_value(maps:get(remote_peer_id, Peer, undefined)),
      crypto_failures => maps:get(crypto_failures, Peer, 0),
      frames_rejected => maps:get(frames_rejected, Peer, 0),
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
