%%%-------------------------------------------------------------------
%% @doc Cowboy handler for the read-only administration dashboard.
%%%-------------------------------------------------------------------
-module(vpn_dashboard_http).

-export([init/2]).

init(Req0, State) ->
    case cowboy_req:method(Req0) of
        <<"GET">> ->
            reply_dashboard(Req0, State);
        _Other ->
            Req = cowboy_req:reply(
                405,
                #{<<"allow">> => <<"GET">>},
                Req0),
            {ok, Req, State}
    end.

reply_dashboard(Req0, State) ->
    try render(vpn_admin:summary_view()) of
        Html ->
            Req = cowboy_req:reply(
                200,
                #{<<"content-type">> => <<"text/html; charset=utf-8">>},
                Html,
                Req0),
            {ok, Req, State}
    catch
        _:_ ->
            Req = cowboy_req:reply(
                500,
                #{<<"content-type">> => <<"text/html; charset=utf-8">>},
                <<"<!doctype html><html><head><title>VPN Dashboard Error</title></head>"
                  "<body><h1>VPN Dashboard Error</h1></body></html>">>,
                Req0),
            {ok, Req, State}
    end.

render(Summary) ->
    Counts = maps:get(counts, Summary, #{}),
    Peers = maps:get(peers, Summary, []),
    iolist_to_binary([
        <<"<!doctype html><html><head><meta charset=\"utf-8\">">>,
        <<"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">">>,
        <<"<title>VPN Dashboard</title>">>,
        style(),
        <<"</head><body><main>">>,
        <<"<h1>VPN Dashboard</h1>">>,
        actions(),
        counts(Counts),
        peers_table(Peers),
        <<"</main></body></html>">>
    ]).

style() ->
    <<"<style>"
      "body{font-family:system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;"
      "margin:0;background:#f6f7f9;color:#17202a;}"
      "main{max-width:1180px;margin:0 auto;padding:32px 20px;}"
      "h1{font-size:28px;margin:0 0 24px;}"
      ".actions{margin:0 0 18px;}"
      ".counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px;}"
      ".count{background:#fff;border:1px solid #d8dee4;border-radius:6px;padding:14px;}"
      ".count span{display:block;color:#57606a;font-size:13px;margin-bottom:8px;}"
      ".count strong{font-size:24px;}"
      "table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d8dee4;border-radius:6px;overflow:hidden;}"
      "th,td{text-align:left;border-bottom:1px solid #d8dee4;padding:10px 12px;font-size:14px;}"
      "th{background:#eef1f4;color:#24292f;font-weight:600;}"
      "tr:last-child td{border-bottom:0;}"
      "form{margin:0;}"
      "button{appearance:none;border:1px solid #57606a;background:#fff;border-radius:6px;"
      "padding:7px 12px;font:inherit;cursor:pointer;}"
      "button:hover{background:#eef1f4;}"
      "</style>">>.

actions() ->
    <<"<section class=\"actions\"><form method=\"post\" action=\"/admin/reload\">"
      "<button type=\"submit\">Reload Config</button>"
      "</form></section>">>.

counts(Counts) ->
    [
        <<"<section class=\"counts\">">>,
        count_card(<<"Configured Peers">>, maps:get(configured, Counts, 0)),
        count_card(<<"Running Peers">>, maps:get(running, Counts, 0)),
        count_card(<<"Stopped Peers">>, maps:get(stopped, Counts, 0)),
        count_card(<<"Certificates">>, maps:get(certificates, Counts, 0)),
        <<"</section>">>
    ].

count_card(Label, Value) ->
    [<<"<div class=\"count\"><span>">>, html_escape(Label), <<"</span><strong>">>,
     html_escape(Value), <<"</strong></div>">>].

peers_table(Peers) ->
    [
        <<"<table><thead><tr>">>,
        table_header(<<"Peer">>),
        table_header(<<"Running">>),
        table_header(<<"Mode">>),
        table_header(<<"IP">>),
        table_header(<<"Remote Peer">>),
        table_header(<<"Trusted">>),
        table_header(<<"Key Match">>),
        table_header(<<"Expires">>),
        table_header(<<"Crypto Failures">>),
        table_header(<<"Frames Rejected">>),
        table_header(<<"Actions">>),
        <<"</tr></thead><tbody>">>,
        [peer_row(Peer) || Peer <- Peers],
        <<"</tbody></table>">>
    ].

table_header(Label) ->
    [<<"<th>">>, html_escape(Label), <<"</th>">>].

peer_row(Peer) ->
    Certificate = maps:get(certificate, Peer, #{}),
    [
        <<"<tr>">>,
        table_cell(maps:get(id, Peer, null)),
        table_cell(yes_no(maps:get(running, Peer, false))),
        table_cell(maps:get(mode, Peer, null)),
        table_cell(maps:get(ip, Peer, null)),
        table_cell(maps:get(remote_peer_id, Peer, null)),
        table_cell(yes_no(maps:get(trusted, Certificate, false))),
        table_cell(yes_no(maps:get(key_match, Certificate, false))),
        table_cell(maps:get(not_after, Certificate, null)),
        table_cell(maps:get(crypto_failures, Peer, 0)),
        table_cell(maps:get(frames_rejected, Peer, 0)),
        table_cell_raw(peer_action(Peer)),
        <<"</tr>">>
    ].

table_cell(Value) ->
    [<<"<td>">>, html_escape(Value), <<"</td>">>].

table_cell_raw(Html) ->
    [<<"<td>">>, Html, <<"</td>">>].

peer_action(Peer) ->
    PeerId = maps:get(id, Peer, null),
    Running = maps:get(running, Peer, false),
    {Action, Label} =
        case Running of
            true ->
                {<<"stop">>, <<"Stop">>};
            false ->
                {<<"start">>, <<"Start">>}
        end,
    [<<"<form method=\"post\" action=\"/admin/peer/">>,
     html_escape(PeerId),
     <<"/">>,
     Action,
     <<"\"><button type=\"submit\">">>,
     Label,
     <<"</button></form>">>].

yes_no(true) ->
    <<"yes">>;
yes_no(false) ->
    <<"no">>;
yes_no(_Value) ->
    <<"no">>.

html_escape(null) ->
    <<>>;
html_escape(Value) when is_binary(Value) ->
    escape_binary(Value);
html_escape(Value) when is_integer(Value) ->
    integer_to_binary(Value);
html_escape(Value) when is_float(Value) ->
    float_to_binary(Value, [{decimals, 6}, compact]);
html_escape(true) ->
    <<"true">>;
html_escape(false) ->
    <<"false">>;
html_escape(Value) when is_atom(Value) ->
    escape_binary(atom_to_binary(Value, utf8));
html_escape(Value) when is_list(Value) ->
    escape_binary(unicode:characters_to_binary(Value));
html_escape(_Value) ->
    <<>>.

escape_binary(Value) ->
    escape_binary(Value, []).

escape_binary(<<>>, Acc) ->
    iolist_to_binary(lists:reverse(Acc));
escape_binary(<<"&", Rest/binary>>, Acc) ->
    escape_binary(Rest, [<<"&amp;">> | Acc]);
escape_binary(<<"<", Rest/binary>>, Acc) ->
    escape_binary(Rest, [<<"&lt;">> | Acc]);
escape_binary(<<">", Rest/binary>>, Acc) ->
    escape_binary(Rest, [<<"&gt;">> | Acc]);
escape_binary(<<"\"", Rest/binary>>, Acc) ->
    escape_binary(Rest, [<<"&quot;">> | Acc]);
escape_binary(<<"'", Rest/binary>>, Acc) ->
    escape_binary(Rest, [<<"&#39;">> | Acc]);
escape_binary(<<Char/utf8, Rest/binary>>, Acc) ->
    escape_binary(Rest, [<<Char/utf8>> | Acc]).
