-module(vpn_openssl_tests).

-include_lib("eunit/include/eunit.hrl").

local_runtime_libraries_are_derived_from_executable_test() ->
    Root = temporary_directory(),
    Bin = filename:join(Root, "bin"),
    Lib64 = filename:join(Root, "lib64"),
    Lib = filename:join(Root, "lib"),
    ok = filelib:ensure_dir(filename:join(Bin, "placeholder")),
    ok = file:make_dir(Lib64),
    ok = file:make_dir(Lib),
    try
        Env = vpn_openssl:environment(filename:join(Bin, "openssl")),
        {"LD_LIBRARY_PATH", Value} = lists:keyfind("LD_LIBRARY_PATH", 1, Env),
        Paths = string:tokens(Value, ":"),
        ?assertEqual([Lib64, Lib], lists:sublist(Paths, 2))
    after
        remove_directory(Root)
    end.

system_executable_without_local_libraries_keeps_empty_environment_test() ->
    Previous = os:getenv("LD_LIBRARY_PATH"),
    PreviousOrig = os:getenv("LD_LIBRARY_PATH_ORIG"),
    true = os:unsetenv("LD_LIBRARY_PATH"),
    true = os:unsetenv("LD_LIBRARY_PATH_ORIG"),
    try
        ?assertEqual([], vpn_openssl:environment("/usr/bin/openssl"))
    after
        restore_env("LD_LIBRARY_PATH", Previous),
        restore_env("LD_LIBRARY_PATH_ORIG", PreviousOrig)
    end.

configured_openssl_runs_with_derived_loader_path_test() ->
    case os:getenv("OPENSSL3") of
        false -> ok;
        _ ->
            {ok, Output} = vpn_openssl:run(["version"]),
            ?assertMatch(<<"OpenSSL ", _/binary>>, Output)
    end.

temporary_directory() ->
    filename:join(os:getenv("TMPDIR", "/tmp"),
                  "vpn-openssl-test-" ++
                  integer_to_list(erlang:unique_integer([positive]))).

remove_directory(Root) ->
    _ = file:del_dir(filename:join(Root, "lib64")),
    _ = file:del_dir(filename:join(Root, "lib")),
    _ = file:del_dir(filename:join(Root, "bin")),
    _ = file:del_dir(Root),
    ok.

restore_env(Name, false) -> os:unsetenv(Name);
restore_env(Name, Value) -> os:putenv(Name, Value).
