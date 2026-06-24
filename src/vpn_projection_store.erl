%%%-------------------------------------------------------------------
%% @doc Backend contract for durable VPN projection snapshots.
%%%-------------------------------------------------------------------
-module(vpn_projection_store).

-export_type([envelope/0]).

-type envelope() :: #{schema_version := pos_integer(),
                      projection_version := non_neg_integer(),
                      checksum := binary(),
                      payload := map(),
                      updated_at := non_neg_integer()}.

-callback load() ->
    not_found |
    {ok, non_neg_integer(), envelope()} |
    {error, term()}.

-callback commit(non_neg_integer(), envelope()) ->
    {ok, non_neg_integer()} |
    {error, term()}.
