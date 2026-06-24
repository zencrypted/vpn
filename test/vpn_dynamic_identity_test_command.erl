-module(vpn_dynamic_identity_test_command).

-export([ensure/3]).

ensure(Paths, Allocation, _Config) ->
    write_fixture_bundle(Paths, Allocation).

write_fixture_bundle(Paths, Allocation) ->
    ClientPeerId = maps:get(client_peer_id, Allocation),
    GatewayPeerId = maps:get(gateway_peer_id, Allocation),
    ClientName = binary_to_list(ClientPeerId),
    CaPath = maps:get(ca_certificate_path, Paths),
    ClientCert = maps:get(client_certificate_path, Paths),
    ClientKey = maps:get(client_private_key_path, Paths),
    ClientCsr = maps:get(client_csr_path, Paths),
    GatewayCert = maps:get(gateway_certificate_path, Paths),
    GatewayKey = maps:get(gateway_private_key_path, Paths),
    GatewayCsr = maps:get(gateway_csr_path, Paths),
    OvpnPath = maps:get(client_ovpn_path, Paths),
    ok = ensure_parent(CaPath),
    ok = ensure_parent(ClientCert),
    ok = ensure_parent(ClientKey),
    ok = ensure_parent(ClientCsr),
    ok = ensure_parent(GatewayCert),
    ok = ensure_parent(GatewayKey),
    ok = ensure_parent(GatewayCsr),
    ok = copy_fixture("ca.crt", CaPath),
    ok = copy_fixture("peer_a.crt", ClientCert),
    ok = copy_fixture("peer_a.key", ClientKey),
    ok = file:change_mode(ClientKey, 8#600),
    ok = file:write_file(ClientCsr, <<"fixture csr for ", ClientPeerId/binary>>),
    ok = copy_fixture("peer_b.crt", GatewayCert),
    ok = copy_fixture("peer_b.key", GatewayKey),
    ok = file:change_mode(GatewayKey, 8#600),
    ok = file:write_file(GatewayCsr, <<"fixture csr for ", GatewayPeerId/binary>>),
    {ok, CaPem} = file:read_file(CaPath),
    {ok, CertPem} = file:read_file(ClientCert),
    Gateway = maps:get(gateway, Allocation),
    RemotePort = integer_to_binary(maps:get(local_udp_port, Gateway)),
    KeyRef = iolist_to_binary(["keys/", ClientName, ".key"]),
    Ovpn = iolist_to_binary([
        "client\n",
        "dev tun\n",
        "proto udp\n",
        "remote 127.0.0.1 ", RemotePort, "\n",
        "nobind\n",
        "persist-key\n",
        "persist-tun\n",
        "remote-cert-tls server\n",
        "<ca>\n", CaPem, "</ca>\n",
        "<cert>\n", CertPem, "</cert>\n",
        "key ", KeyRef, "\n"
    ]),
    ok = file:write_file(OvpnPath, Ovpn),
    ok.

ensure_parent(Path) -> filelib:ensure_dir(Path).

copy_fixture(Name, Destination) ->
    Source = filename:join([code:priv_dir(vpn), "certs", Name]),
    {ok, Binary} = file:read_file(Source),
    file:write_file(Destination, Binary).
