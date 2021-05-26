# Zeek script that watches for duplicate DNS query replies.

global query_and_id: set[string, int] &write_expire=1 min;

event dns_query_reply (c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
  if([c$dns$query, c$dns$trans_id] in query_and_id){
    print fmt ("Possible DNS cache poisoning attempt --> Source IP: %s, Destination IP: %s, Query: %s", c$id$orig_h, c$id$resp_h, c$dns$query);
    return;
  }
  if(!([c$dns$query, c$dns$trans_id] in query_and_id)){
    add query_and_id[c$dns$query, c$dns$trans_id];
  }
}
