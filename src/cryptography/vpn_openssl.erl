%%%-------------------------------------------------------------------
%% @doc OpenSSL executable selection and process runner.
%%
%% Local OpenSSL installations commonly keep libssl/libcrypto beside the
%% executable prefix rather than in the system loader path. The runner derives
%% those directories from bin/openssl and passes them explicitly to open_port.
%%%-------------------------------------------------------------------
-module(vpn_openssl).

-export([executable/0, environment/1, run/1]).

-spec executable() -> {ok, file:filename()} | {error, openssl_not_found}.
executable() ->
    find_candidate([os:getenv("OPENSSL3"),
                    os:getenv("OPENSSL"),
                    "openssl"]).

-spec run([string()]) -> {ok, binary()} | {error, term()}.
run(Args) when is_list(Args) ->
    case executable() of
        {ok, Executable} ->
            Options0 = [binary, exit_status, use_stdio, stderr_to_stdout,
                        {args, Args}],
            Options = case environment(Executable) of
                          [] -> Options0;
                          Env -> [{env, Env} | Options0]
                      end,
            Port = open_port({spawn_executable, Executable}, Options),
            collect_port(Port, []);
        {error, _} = Error ->
            Error
    end.

-spec environment(file:filename()) -> [{string(), string()}].
environment(Executable) ->
    Prefix = filename:dirname(filename:dirname(Executable)),
    LocalDirectories = [Directory || Directory <-
                                         [filename:join(Prefix, "lib64"),
                                          filename:join(Prefix, "lib")],
                                     filelib:is_dir(Directory)],
    Existing = existing_library_path(),
    case unique_paths(LocalDirectories ++ split_paths(Existing)) of
        [] -> [];
        Paths -> [{"LD_LIBRARY_PATH", string:join(Paths, ":")}]
    end.

find_candidate([]) ->
    {error, openssl_not_found};
find_candidate([false | Rest]) ->
    find_candidate(Rest);
find_candidate(["" | Rest]) ->
    find_candidate(Rest);
find_candidate([Candidate | Rest]) ->
    case resolve_candidate(Candidate) of
        {ok, _} = Found -> Found;
        {error, openssl_not_found} -> find_candidate(Rest)
    end.

resolve_candidate(Candidate) ->
    case filename:pathtype(Candidate) of
        absolute ->
            case filelib:is_regular(Candidate) of
                true -> {ok, Candidate};
                false -> {error, openssl_not_found}
            end;
        _ ->
            case os:find_executable(Candidate) of
                false -> {error, openssl_not_found};
                Path -> {ok, Path}
            end
    end.

existing_library_path() ->
    case os:getenv("LD_LIBRARY_PATH") of
        false ->
            case os:getenv("LD_LIBRARY_PATH_ORIG") of
                false -> "";
                Value -> Value
            end;
        Value -> Value
    end.

split_paths("") -> [];
split_paths(Value) -> string:tokens(Value, ":").

unique_paths(Paths) ->
    unique_paths(Paths, #{}, []).

unique_paths([], _Seen, Acc) -> lists:reverse(Acc);
unique_paths(["" | Rest], Seen, Acc) -> unique_paths(Rest, Seen, Acc);
unique_paths([Path | Rest], Seen, Acc) ->
    case maps:is_key(Path, Seen) of
        true -> unique_paths(Rest, Seen, Acc);
        false -> unique_paths(Rest, Seen#{Path => true}, [Path | Acc])
    end.

collect_port(Port, Acc) ->
    receive
        {Port, {data, Data}} ->
            collect_port(Port, [Acc, Data]);
        {Port, {exit_status, 0}} ->
            {ok, iolist_to_binary(Acc)};
        {Port, {exit_status, Status}} ->
            {error, {openssl_exit_status, Status, iolist_to_binary(Acc)}}
    after 10000 ->
        catch port_close(Port),
        {error, openssl_timeout}
    end.
