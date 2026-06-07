%%%-------------------------------------------------------------------
%% @doc Minimal read-only N2O/Nitro administration dashboard skeleton.
%%%-------------------------------------------------------------------
-module(vpn_n2o_admin).

-include_lib("nitro/include/nitro.hrl").

-export([init/2]).

init(Req0, State) ->
    case cowboy_req:method(Req0) of
        <<"GET">> ->
            reply_page(Req0, State);
        _Other ->
            Req = cowboy_req:reply(
                405,
                #{<<"allow">> => <<"GET">>},
                Req0),
            {ok, Req, State}
    end.

reply_page(Req0, State) ->
    try render(vpn_admin:summary_view()) of
        Html ->
            Req = cowboy_req:reply(
                200,
                #{<<"content-type">> => <<"text/html; charset=utf-8">>},
                Html,
                Req0),
            {ok, Req, State}
    catch
        Class:Reason:Stack ->
            logger:error("N2O dashboard render failed: ~p:~p~n~p",
                         [Class, Reason, Stack]),
            Req = cowboy_req:reply(
                500,
                #{<<"content-type">> => <<"text/html; charset=utf-8">>},
                <<"<!doctype html><html><head><title>VPN Dashboard N2O Error</title></head>"
                  "<body><h1>VPN Dashboard N2O Error</h1></body></html>">>,
                Req0),
            {ok, Req, State}
    end.

render(Summary) ->
    Counts = maps:get(counts, Summary, #{}),
    Peers = maps:get(peers, Summary, []),
    Body = nitro:render([
        #main{
            body = [
                #h1{body = <<"VPN Dashboard (N2O)">>},
                render_counts(Counts),
                render_peer_table(Peers),
                #p{class = <<"runtime">>,
                   body = [<<"N2O ">>, n2o_version(), <<" / Nitro rendered">>]}
            ]
        }
    ]),
    iolist_to_binary([
        <<"<!doctype html><html><head><meta charset=\"utf-8\">">>,
        <<"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">">>,
        <<"<title>VPN Dashboard (N2O)</title>">>,
        style(),
        <<"</head><body>">>,
        Body,
        <<"</body></html>">>
    ]).

render_counts(Counts) ->
    #section{
        class = <<"counts">>,
        body = [
            count_card(<<"Configured Peers">>, maps:get(configured, Counts, 0)),
            count_card(<<"Running Peers">>, maps:get(running, Counts, 0)),
            count_card(<<"Stopped Peers">>, maps:get(stopped, Counts, 0)),
            count_card(<<"Certificates">>, maps:get(certificates, Counts, 0))
        ]
    }.

count_card(Label, Value) ->
    #panel{
        class = <<"count">>,
        body = [
            #span{body = Label},
            #span{class = <<"value">>, body = integer_to_binary(Value)}
        ]
    }.

render_peer_table(Peers) ->
    HeaderRow = #tr{cells = [header_cell(Label) || Label <- table_headers()]},
    Rows = [render_peer_row(Peer) || Peer <- Peers],
    #table{
        header = HeaderRow,
        body = #tbody{body = Rows}
    }.

table_headers() ->
    [
        <<"Peer">>,
        <<"Running">>,
        <<"Mode">>,
        <<"IP">>,
        <<"Remote Peer">>,
        <<"Trusted">>,
        <<"Key Match">>,
        <<"Expires">>,
        <<"Crypto Failures">>,
        <<"Frames Rejected">>
    ].

header_cell(Label) ->
    #th{body = Label}.

render_peer_row(Peer) ->
    Certificate = maps:get(certificate, Peer, #{}),
    #tr{
        cells = [
            cell(maps:get(id, Peer, null)),
            cell(yes_no(maps:get(running, Peer, false))),
            cell(maps:get(mode, Peer, null)),
            cell(maps:get(ip, Peer, null)),
            cell(maps:get(remote_peer_id, Peer, null)),
            cell(yes_no(maps:get(trusted, Certificate, false))),
            cell(yes_no(maps:get(key_match, Certificate, false))),
            cell(maps:get(not_after, Certificate, null)),
            cell(maps:get(crypto_failures, Peer, 0)),
            cell(maps:get(frames_rejected, Peer, 0))
        ]
    }.

cell(Value) ->
    #td{body = value(Value)}.

yes_no(true) ->
    <<"yes">>;
yes_no(false) ->
    <<"no">>;
yes_no(_Value) ->
    <<"no">>.

value(null) ->
    <<>>;
value(undefined) ->
    <<>>;
value(Value) when is_binary(Value) ->
    Value;
value(Value) when is_integer(Value) ->
    integer_to_binary(Value);
value(Value) when is_float(Value) ->
    float_to_binary(Value, [{decimals, 6}, compact]);
value(true) ->
    <<"true">>;
value(false) ->
    <<"false">>;
value(Value) when is_atom(Value) ->
    atom_to_binary(Value, utf8);
value(Value) when is_list(Value) ->
    unicode:characters_to_binary(Value);
value(_Value) ->
    <<>>.

style() ->
    <<"<style>"
      "body{font-family:system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;"
      "margin:0;background:#f6f7f9;color:#17202a;}"
      "main{max-width:1180px;margin:0 auto;padding:32px 20px;}"
      "h1{font-size:28px;margin:0 0 24px;}"
      ".counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px;}"
      ".count{background:#fff;border:1px solid #d8dee4;border-radius:6px;padding:14px;}"
      ".count span{display:block;color:#57606a;font-size:13px;margin-bottom:8px;}"
      ".count .value{font-size:24px;color:#17202a;}"
      "table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d8dee4;border-radius:6px;overflow:hidden;}"
      "th,td{text-align:left;border-bottom:1px solid #d8dee4;padding:10px 12px;font-size:14px;}"
      "th{background:#eef1f4;color:#24292f;font-weight:600;}"
      "tr:last-child td{border-bottom:0;}"
      ".runtime{color:#57606a;font-size:13px;}"
      "</style>">>.

n2o_version() ->
    case n2o:version() of
        undefined ->
            <<"unknown">>;
        Version ->
            nitro:to_binary(Version)
    end.
