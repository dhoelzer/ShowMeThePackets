@load base/protocols/conn/main.bro

module Outbound;

export {
	redef enum Log::ID += { LOG };
	type Info: record {
		ts: time	&log;
		id: conn_id	&log;
		uid: string	&log;
		proto: string	&log;
		};

	const internal_networks: set[subnet] = {
		10.0.0.0/8
	};

	const bro_manager: set[addr] = {
		10.186.52.51
	};

	const known_endpoints: set[addr] = {
		108.60.137.12,
		169.254.169.254,
		8.8.8.8
	};

	const whitelisted_services: set[port] = {
		123/udp,
		67/udp
	};
}

event bro_init()
{
	Log::create_stream(Outbound::LOG, [$columns=Info, $path="outbound"]);
}

function log_it(c:connection, proto:string)
{
                local rec: Outbound::Info = [$ts=network_time(), $id = c$id, $uid = c$uid, $proto = proto];
                Log::write(Outbound::LOG, rec);
}
event connection_attempt(c: connection)
{
        if(c$id$orig_h in bro_manager && c$id$resp_h in internal_networks){ return; }
	if(c$id$orig_h in internal_networks && c$id$resp_h in internal_networks) { return; }
        if(c$id$orig_h in internal_networks && c$id$resp_h !in known_endpoints)
        {
                log_it(c, "tcp");
        }
}

event connection_established(c: connection)
{
	if(c$id$orig_h in bro_manager && c$id$resp_h in internal_networks){ return; }
        if(c$id$orig_h in internal_networks && c$id$resp_h in internal_networks) { return; }
	if(c$id$orig_h in internal_networks && c$id$resp_h !in known_endpoints && c$orig$state == TCP_ESTABLISHED)
	{
		log_it(c, "tcp");
	}	
}

event icmp_sent(c:connection, icmp:icmp_conn)
{
        if(c$id$orig_h in bro_manager && c$id$resp_h in internal_networks){ return; }
        if(c$id$orig_h in internal_networks && c$id$resp_h in internal_networks) { return; }
        if(c$id$orig_h in internal_networks && c$id$resp_h !in known_endpoints)
        {
		log_it(c, "icmp");
        }
}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
{
        if(c$id$orig_h in bro_manager && c$id$resp_h in internal_networks){ return; }
        if(c$id$orig_h in internal_networks && c$id$resp_h in internal_networks) { return; }
        if(c$id$orig_h in internal_networks && c$id$resp_h !in known_endpoints)
        {
		log_it(c, "icmp");
        }
}

event udp_request(c:connection)
{
        if(c$id$orig_h in bro_manager && c$id$resp_h in internal_networks){ return; }
        if(c$id$orig_h in internal_networks && c$id$resp_h in internal_networks) { return; }
	if(c$id$resp_p in whitelisted_services) { return; }
	if(c$id$orig_p in whitelisted_services) { return; }
        if(c$id$orig_h in internal_networks && c$id$resp_h !in known_endpoints)
        {
		log_it(c, "udp");
        }
}

event udp_reply(c:connection)
{
        if(c$id$resp_p in whitelisted_services) { return; }
        if(c$id$orig_p in whitelisted_services) { return; }
        if(c$id$orig_h in bro_manager && c$id$resp_h in internal_networks){ return; }
        if(c$id$orig_h in internal_networks && c$id$resp_h in internal_networks) { return; }
        if(c$id$orig_h in internal_networks && c$id$resp_h !in known_endpoints)
        {
		log_it(c, "udp");
        }
}
