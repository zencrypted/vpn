%%%-------------------------------------------------------------------
%% @doc Minimal read-only N2O/Nitro administration dashboard skeleton.
%%%-------------------------------------------------------------------
-module(vpn_n2o_admin).

-include_lib("nitro/include/cx.hrl").
-include_lib("nitro/include/nitro.hrl").

-export([init/2,
         cx/2,
         event/1,
         refresh_dashboard/0]).

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
    nitro:actions([]),
    Counts = maps:get(counts, Summary, #{}),
    Peers = maps:get(peers, Summary, []),
    Body = nitro:render([
        #main{
            body = [
                #h1{body = <<"VPN Dashboard (N2O)">>},
                render_actions(),
                render_message(<<>>),
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
        scripts(),
        <<"</body></html>">>
    ]).

render_actions() ->
    #section{
        class = <<"actions">>,
        body = [
            #button{
                body = <<"Reload Config">>,
                onclick = <<"direct(atom('reload_config'));">>
            }
        ]
    }.

render_message(Message) ->
    #panel{
        id = <<"dashboard_messages">>,
        class = <<"messages">>,
        body = Message
    }.

render_counts(Counts) ->
    #section{
        id = <<"dashboard_counts">>,
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
        id = <<"dashboard_peers">>,
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
        <<"Frames Rejected">>,
        <<"Actions">>
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
            cell(maps:get(frames_rejected, Peer, 0)),
            action_cell(Peer)
        ]
    }.

cell(Value) ->
    #td{body = value(Value)}.

action_cell(Peer) ->
    PeerId = maps:get(id, Peer, null),
    Running = maps:get(running, Peer, false),
    #td{body = action_button(PeerId, Running)}.

action_button(PeerId, true) ->
    #button{
        body = <<"Stop">>,
        onclick = direct_peer_event(<<"stop_peer">>, PeerId)
    };
action_button(PeerId, false) ->
    #button{
        body = <<"Start">>,
        onclick = direct_peer_event(<<"start_peer">>, PeerId)
    }.

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
      ".actions{margin:0 0 18px;}"
      ".messages{min-height:20px;margin:0 0 14px;color:#57606a;font-size:14px;}"
      ".counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px;}"
      ".count{background:#fff;border:1px solid #d8dee4;border-radius:6px;padding:14px;}"
      ".count span{display:block;color:#57606a;font-size:13px;margin-bottom:8px;}"
      ".count .value{font-size:24px;color:#17202a;}"
      "table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d8dee4;border-radius:6px;overflow:hidden;}"
      "th,td{text-align:left;border-bottom:1px solid #d8dee4;padding:10px 12px;font-size:14px;}"
      "th{background:#eef1f4;color:#24292f;font-weight:600;}"
      "tr:last-child td{border-bottom:0;}"
      "button{appearance:none;border:1px solid #57606a;background:#fff;border-radius:6px;"
      "padding:7px 12px;font:inherit;cursor:pointer;}"
      "button:hover{background:#eef1f4;}"
      ".runtime{color:#57606a;font-size:13px;}"
      "</style>">>.

scripts() ->
    [
        <<"<script>var port = window.location.port || \"\";</script>">>,
        <<"<script src=\"/n2o/utf8.js\"></script>">>,
        <<"<script src=\"/n2o/bert.js\"></script>">>,
        <<"<script src=\"/n2o/heart.js\"></script>">>,
        <<"<script src=\"/n2o/n2o.js\"></script>">>,
        <<"<script src=\"/nitro/js/nitro.js\"></script>">>,
        <<"<script>N2O_start();</script>">>
    ].

direct_peer_event(Event, PeerId) ->
    EscapedPeerId = nitro:js_escape(value(PeerId)),
    [<<"direct(tuple(atom('">>, Event, <<"'),bin('">>, EscapedPeerId, <<"')));">>].

n2o_version() ->
    case n2o:version() of
        undefined ->
            <<"unknown">>;
        Version ->
            nitro:to_binary(Version)
    end.

event({start_peer, PeerIdValue}) ->
    PeerIdBin = value(PeerIdValue),
    Message =
        case find_peer_id(PeerIdBin) of
            {ok, PeerId} ->
                action_message(start, PeerIdBin, vpn_manager:start_peer(PeerId));
            {error, not_found} ->
                log_action_error(start, PeerIdBin, not_found),
                <<"Peer not found">>
        end,
    refresh_dashboard(Message);
event({stop_peer, PeerIdValue}) ->
    PeerIdBin = value(PeerIdValue),
    Message =
        case find_peer_id(PeerIdBin) of
            {ok, PeerId} ->
                action_message(stop, PeerIdBin, vpn_manager:stop_peer(PeerId));
            {error, not_found} ->
                log_action_error(stop, PeerIdBin, not_found),
                <<"Peer not found">>
        end,
    refresh_dashboard(Message);
event(reload_config) ->
    Message = reload_message(vpn_manager:reload_config()),
    refresh_dashboard(Message);
event(init) ->
    ok;
event(_Event) ->
    ok.

refresh_dashboard() ->
    refresh_dashboard(<<>>).

refresh_dashboard(Message) ->
    Summary = vpn_admin:summary_view(),
    Counts = maps:get(counts, Summary, #{}),
    Peers = maps:get(peers, Summary, []),
    nitro:update(dashboard_messages, render_message(Message)),
    nitro:update(dashboard_counts, render_counts(Counts)),
    nitro:update(dashboard_peers, render_peer_table(Peers)),
    ok.

action_message(start, PeerIdBin, {ok, _Pid}) ->
    [<<"Peer ">>, PeerIdBin, <<" started">>];
action_message(start, PeerIdBin, {error, already_started}) ->
    log_action_error(start, PeerIdBin, already_started),
    [<<"Peer ">>, PeerIdBin, <<" already started">>];
action_message(start, PeerIdBin, {error, Reason}) ->
    log_action_error(start, PeerIdBin, Reason),
    [<<"Failed to start peer ">>, PeerIdBin];
action_message(stop, PeerIdBin, ok) ->
    [<<"Peer ">>, PeerIdBin, <<" stopped">>];
action_message(stop, PeerIdBin, {error, Reason}) ->
    log_action_error(stop, PeerIdBin, Reason),
    [<<"Failed to stop peer ">>, PeerIdBin].

reload_message(#{failed := []}) ->
    <<"Configuration reloaded">>;
reload_message(#{failed := Failed}) ->
    logger:warning("N2O dashboard reload completed with failures: ~p", [Failed]),
    <<"Configuration reloaded with failures">>;
reload_message(Result) ->
    logger:info("N2O dashboard reload completed: ~p", [Result]),
    <<"Configuration reloaded">>.

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

log_action_error(Action, PeerIdBin, Reason) ->
    logger:warning("N2O dashboard peer action failed action=~p peer=~s reason=~p",
                   [Action, PeerIdBin, Reason]).

cx(Cookies, Req) ->
    Token =
        case lists:keyfind(<<"X-Auth-Token">>, 1, Cookies) of
            {_, Value} ->
                Value;
            false ->
                <<>>
        end,
    Sid =
        case n2o:depickle(Token) of
            {{Session, _}, _} ->
                Session;
            _Other ->
                <<>>
        end,
    #cx{actions = [],
        path = cowboy_req:path(Req),
        req = Req,
        params = [],
        session = Sid,
        token = Token,
        module = ?MODULE,
        handlers = []}.
