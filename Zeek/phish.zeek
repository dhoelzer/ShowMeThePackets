global domains_in_emails: set[string];
global addresses_from_links: set[addr];

event mime_entity_data (c: connection, length: count, data: string)
{
  local urls = find_all(data, /https*:\/\/[^\/]*/);
  if(|urls| == 0){ return; }
  for(url in urls){
	add domains_in_emails[split_string(url, /\//)[2]];
  }
}

event dns_A_reply (c: connection, msg: dns_msg, ans: dns_answer, a: addr)
{
  if(ans$query in domains_in_emails){
    add addresses_from_links[a];
  }
}

event connection_SYN_packet (c: connection, pkt: SYN_packet)
{
  if(!(c$id$resp_h in addresses_from_links)) { return; }
  if(c$id$resp_p == 80/tcp) {
    print fmt ("Phishing related: HTTP connection from %s to %s", c$id$orig_h, c$id$resp_h);
    return;
  }
  if(c$id$resp_p == 443/tcp) {
    print fmt ("Phishing related: TLS/SSL connection from %s to %s", c$id$orig_h, c$id$resp_h);
    return;
  }
  print fmt (">>> Phishing related: connection to port %d from %s to %s", c$id$resp_p, c$id$orig_h, c$id$resp_h);

}