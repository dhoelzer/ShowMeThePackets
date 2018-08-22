# Example behavior detection script for Bro-IDS
# Available from http://github.com/dhoelzer/AuditcastsScripts/Bro
#
# Find URLs in MIME content. For all URLs found, record the host name.
# Identify DNS lookups that involve host names that appeared in MIME data. Record the addresses.
# Find outbound web and other connections to addresses identified above and generate alerts.

global host_names_in_emails:	string_set;
global possible_bad_addresses:	addr_set;


event mime_entity_data(c: connection, length: count, data: string)
{
  for (a in find_all(data, /http:\/\/[^\/]+/))
  {
    add host_names_in_emails[split(a, /\//)[3]];
  }
}


event dns_A_reply(c:connection, msg:dns_msg, ans:dns_answer, a:addr)
{
  if(ans$query in host_names_in_emails)
  {
    add possible_bad_addresses[a];
  }
}

event http_request(c:connection, method:string, original_URI:string, unescaped_URI:string, version:string)
{
  if(c$id$resp_h in possible_bad_addresses)
  {
    print fmt(">> Web request to %s found in email!  Requested URL -> %s", c$id$resp_h, original_URI);
  }
}


event connection_SYN_packet(c: connection, pkt: SYN_packet)
{
	if(c$id$resp_h in possible_bad_addresses)
	{
		if(c$id$resp_p == 80/tcp)
		{
			print fmt(">> Possible Phish: Outbound connection from %s to %s : %s", c$id$orig_h, c$id$resp_h, c$id$resp_p);
		} else {
			print fmt(">> Possible C&C!! Outbound connection from %s to %s : %s", c$id$orig_h, c$id$resp_h, c$id$resp_p);
		}

	}
}
