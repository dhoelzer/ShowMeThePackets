module ContentForML;

# We must instruct Zeek to  deliver content to us or it delivers none or only certain protocols.
redef udp_content_deliver_all_orig=T;
redef udp_content_deliver_all_resp=T;

const LENGTH=16;

redef exit_only_after_terminate = T;

global categorizeStream: event(orig_h:addr, orig_p:port, resp_h:addr, resp_p:port, content: string);

event zeek_init()
	{
	Broker::subscribe("sec503/content");
	Broker::listen("127.0.0.1", 9999/tcp);
	Broker::auto_publish("sec503/content", categorizeStream);
	}
	
function output(c:connection, bytes: string)
{
  Broker::publish("sec503/content", categorizeStream, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, string_to_ascii_hex(sub_bytes(bytes, 0, LENGTH))
);
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
#return;
  if(seq==1 && |payload|>0 &&  "S" in c$history)
  {
#	print(c);
	output(c, payload);
  }
}
event udp_contents(c:connection, is_orig:bool, content:string)
{
return;
  if(is_orig == F && c$id$resp_p==67/udp)
  {
#	print fmt("%s -> %s", c$id$orig_p, c$id$resp_p);
	output(c, content);
  }
}
