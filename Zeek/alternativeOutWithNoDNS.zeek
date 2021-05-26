# Find outbound new_connections that have no matching DNS resolution.

global whitelist: set[addr] = {
	8.8.8.8
};
global  internalNets: set[subnet] = { 192.168.0.0/16 };
global resolvedAddresses:set[addr];

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	add resolvedAddresses[a];
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	add resolvedAddresses[a];
	}

event new_connection(c: connection)
	{
		if(c$id$orig_h ! in internalNets || c$id$resp_h in internalNets)
			{
			return;
			}
		if(c$id$resp_h in resolvedAddresses || c$id$resp_h in whitelist)
			{
			return;
			}
		print fmt("%s:%s -> %s:%s - No DNS lookup", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
	}