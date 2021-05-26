# Bro script to find outbound connections for which there are no corresponding DNS lookups.
# David Hoelzer, Enclave Forensics, Inc - Copyright 2018

global knownAddresses: set[addr] &read_expire = 7 days;
global internalAddresses: set[subnet] = {192.168.0.0/16};

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a:addr)
{
	add knownAddresses[a];
}

event new_connection(c: connection)
{
	if(c$id$orig_h !in internalAddresses) { return; }
	if(c$id$resp_h in internalAddresses) { return; }
	if(c$id$resp_h in knownAddresses) { return; }

	local message: string;
	message = fmt("Outbound connection %s:%s > %s:%s without a DNS lookup.", c$id$orig_h, c$id$orig_p,
		c$id$resp_h, c$id$resp_p);
	NOTICE([$note=Weird::Activity, $msg=message, $conn=c]);
}