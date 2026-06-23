%%%-------------------------------------------------------------------
%% @doc Session lifecycle metadata for authenticated traffic-key epochs.
%%%-------------------------------------------------------------------
-module(vpn_session_lifecycle).

-export([new/1, record_tx/2, record_rx/2, info/1, info/2]).

new(KeyEpoch) when is_integer(KeyEpoch), KeyEpoch > 0 ->
    Now = erlang:system_time(second),
    #{established_at => Now,
      last_rekey_at => Now,
      key_epoch => KeyEpoch,
      tx_packets_since_rekey => 0,
      tx_bytes_since_rekey => 0,
      rx_packets_since_rekey => 0,
      rx_bytes_since_rekey => 0}.

record_tx(Size, State) when is_integer(Size), Size >= 0 ->
    State#{tx_packets_since_rekey := maps:get(tx_packets_since_rekey, State) + 1,
           tx_bytes_since_rekey := maps:get(tx_bytes_since_rekey, State) + Size}.

record_rx(Size, State) when is_integer(Size), Size >= 0 ->
    State#{rx_packets_since_rekey := maps:get(rx_packets_since_rekey, State) + 1,
           rx_bytes_since_rekey := maps:get(rx_bytes_since_rekey, State) + Size}.

info(State) ->
    info(State, erlang:system_time(second)).

info(State, Now) when is_integer(Now) ->
    EstablishedAt = maps:get(established_at, State),
    TxPackets = maps:get(tx_packets_since_rekey, State),
    RxPackets = maps:get(rx_packets_since_rekey, State),
    TxBytes = maps:get(tx_bytes_since_rekey, State),
    RxBytes = maps:get(rx_bytes_since_rekey, State),
    State#{session_age_seconds => max(0, Now - EstablishedAt),
           packets_since_rekey => TxPackets + RxPackets,
           bytes_since_rekey => TxBytes + RxBytes}.
