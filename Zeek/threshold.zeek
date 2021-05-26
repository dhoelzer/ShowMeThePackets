@load base/protocols/conn/main.bro

module Thresholds;

export {
  redef enum Notice::Type += {
    Byte_Threshold_Exceeded,
  };
}

event connection_established(c: connection)
{
	set_current_conn_bytes_threshold(c$id, 10000000, T);
	set_current_conn_bytes_threshold(c$id, 10000000, F);
}

event conn_bytes_threshold_crossed(c:connection, threshold:count, is_orig:bool)
{
       local cpp = get_conn_transport_proto(c$id);
       local proto = "unknown";
       if(cpp == tcp) { proto = "tcp"; }
       if(cpp == udp) { proto = "udp"; }
       if(cpp == icmp) { proto = "icmp"; }
  local msg = "";
  if(is_orig) {
    msg = fmt("Originator crossed threshold of %d bytes in %d", threshold, c$duration);
    threshold = threshold * 2;
    set_current_conn_bytes_threshold(c$id, threshold, T);
  }
  if(!is_orig) {
    msg = fmt("Respondent crossed threshold of %d", threshold);
    threshold = threshold * 2;
    set_current_conn_bytes_threshold(c$id, threshold, F);
  }
  NOTICE([$note=Byte_Threshold_Exceeded, $msg=msg, $conn=c, $sub="Byte Threshold Crossed"]);
}	
