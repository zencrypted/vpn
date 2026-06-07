%%%-------------------------------------------------------------------
%% @doc Read-only administration facade.
%%%-------------------------------------------------------------------
-module(vpn_admin).

-export([dashboard/0, summary/0, overview/0, peer_counts/0]).

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
