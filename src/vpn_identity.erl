%%%-------------------------------------------------------------------
%% @doc Certificate identity metadata loader.
%%%-------------------------------------------------------------------
-module(vpn_identity).

-export([load/1, safe_info/1]).

load(Config) when is_map(Config) ->
    case required_identity_key(Config) of
        none ->
            load_files(Config);
        {missing, Key} ->
            {error, {missing_identity_key, Key}}
    end;
load(_Config) ->
    {error, invalid_config}.

safe_info(Identity) ->
    maps:with([peer_id, certificate_path, private_key_path], Identity).

load_files(Config) ->
    CertPath = maps:get(certificate_path, Config),
    KeyPath = maps:get(private_key_path, Config),
    case file:read_file(CertPath) of
        {ok, CertPem} ->
            load_key(Config, CertPath, KeyPath, CertPem);
        {error, Reason} ->
            {error, {certificate_read_failed, CertPath, Reason}}
    end.

load_key(Config, CertPath, KeyPath, CertPem) ->
    case file:read_file(KeyPath) of
        {ok, KeyPem} ->
            {ok, #{peer_id => maps:get(id, Config),
                   certificate_path => CertPath,
                   private_key_path => KeyPath,
                   certificate_pem => CertPem,
                   private_key_pem => KeyPem}};
        {error, Reason} ->
            {error, {private_key_read_failed, KeyPath, Reason}}
    end.

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
