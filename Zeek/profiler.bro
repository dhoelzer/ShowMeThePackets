# Zeek script to profile hosts and who they talk to.  The idea is to identify when someone is speaking
# an unusually high (out of profile) number of different hosts.  Should this be DNS driven or IP driven?
# Don't know.  Leaning toward DNS driven for the first pass.

global myNets: set[subnet] = {192.168.0.0/16};

global hostDNSProfiles: table[addr] of table[string] of count;

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
{
    local host = c$id$orig_h;
    if(host !in myNets) { return; }
    if(host !in hostDNSProfiles) {
        (hostDNSProfiles[host]) = table();
    }
    if(ans$query !in hostDNSProfiles[host]){
        (hostDNSProfiles[host])[ans$query] = 0;
    } 
    (hostDNSProfiles[host])[ans$query] = (hostDNSProfiles[host])[ans$query] + 1;
}

event bro_done()
{
    for(host in hostDNSProfiles) { print fmt("%s looked up %s hosts", host, |hostDNSProfiles[host]|); }
}