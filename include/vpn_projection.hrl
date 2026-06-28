-ifndef(VPN_PROJECTION_HRL).
-define(VPN_PROJECTION_HRL, true).

-record(vpn_projection, {
    id = current,
    schema_version = 2,
    projection_version = 0,
    checksum = <<>>,
    payload = #{allocator => #{}, provisioning => #{}},
    updated_at = 0
}).

-endif.
