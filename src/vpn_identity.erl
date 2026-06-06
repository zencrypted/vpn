%%%-------------------------------------------------------------------
%% @doc Certificate identity metadata loader.
%%%-------------------------------------------------------------------
-module(vpn_identity).

-export([load/1]).

load(Config) when is_map(Config) ->
    case required_identity_key(Config) of
        none ->
            {ok, #{peer_id => maps:get(id, Config),
                   certificate_path => maps:get(certificate_path, Config),
                   private_key_path => maps:get(private_key_path, Config)}};
        {missing, Key} ->
            {error, {missing_identity_key, Key}}
    end;
load(_Config) ->
    {error, invalid_config}.

required_identity_key(Config) ->
    required_identity_key(Config, [certificate_path, private_key_path]).

required_identity_key(_Config, []) ->
    none;
required_identity_key(Config, [Key | Rest]) ->
    case maps:is_key(Key, Config) of
        true ->
            required_identity_key(Config, Rest);
        false ->
            {missing, Key}
    end.
