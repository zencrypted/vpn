%%%-------------------------------------------------------------------
%% @doc Production command adapter for the development identity factory.
%%
%% Arguments are passed through spawn_executable rather than a shell. The
%% helper script performs local CA/bootstrap work and never writes key bodies
%% into Erlang state or command output returned to callers.
%%%-------------------------------------------------------------------
-module(vpn_dynamic_identity_command).

-export([ensure/3]).

-spec ensure(map(), map(), map()) -> ok | {error, term()}.
ensure(Paths, Allocation, Config) ->
    ToolPath = maps:get(tool_path, Config),
    case executable(ToolPath) of
        {ok, Tool} ->
            Client = maps:get(client, Allocation),
            Gateway = maps:get(gateway, Allocation),
            Args = ["--allocation-id", text(maps:get(allocation_id, Allocation)),
                    "--client-peer-id", text(maps:get(client_peer_id, Allocation)),
                    "--gateway-peer-id", text(maps:get(gateway_peer_id, Allocation)),
                    "--remote", remote_text(maps:get(remote_ip, Client)),
                    "--gateway-port", integer_to_list(maps:get(local_udp_port, Gateway)),
                    "--output-dir", maps:get(bundle_dir, Paths),
                    "--ca-dir", maps:get(ca_dir, Paths)],
            run(Tool, Args);
        {error, _} = Error ->
            Error
    end.

executable(Path) when is_binary(Path) ->
    executable(binary_to_list(Path));
executable(Path) when is_list(Path) ->
    case filename:pathtype(Path) of
        absolute ->
            case filelib:is_regular(Path) of
                true -> {ok, Path};
                false -> {error, {dynamic_identity_tool_not_found, Path}}
            end;
        _ ->
            Absolute = filename:absname(Path),
            case filelib:is_regular(Absolute) of
                true -> {ok, Absolute};
                false -> {error, {dynamic_identity_tool_not_found, Path}}
            end
    end;
executable(Path) ->
    {error, {invalid_dynamic_identity_tool_path, Path}}.

run(Tool, Args) ->
    Port = open_port({spawn_executable, Tool},
                     [binary, exit_status, use_stdio, stderr_to_stdout,
                      {args, Args}]),
    collect(Port, [], 60000).

collect(Port, Acc, Timeout) ->
    receive
        {Port, {data, Data}} ->
            collect(Port, [Acc, Data], Timeout);
        {Port, {exit_status, 0}} ->
            ok;
        {Port, {exit_status, Status}} ->
            {error, {dynamic_identity_command_failed,
                     Status,
                     truncate(iolist_to_binary(Acc))}}
    after Timeout ->
        catch port_close(Port),
        {error, dynamic_identity_command_timeout}
    end.

truncate(Binary) when byte_size(Binary) =< 4096 -> Binary;
truncate(Binary) -> binary:part(Binary, 0, 4096).

text(Value) when is_binary(Value) -> binary_to_list(Value);
text(Value) when is_list(Value) -> Value.

remote_text({A, B, C, D}) ->
    lists:flatten(io_lib:format("~B.~B.~B.~B", [A, B, C, D]));
remote_text(Value) when is_binary(Value) -> binary_to_list(Value);
remote_text(Value) when is_list(Value) -> Value.
