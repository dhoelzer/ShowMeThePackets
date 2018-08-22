@load base/protocols/conn
@load base/utils/time


# This is probably not so great to reach into the Conn namespace..
module Conn;

export {
function set_conn_log_data_hack(c: connection)
	{
	Conn::set_conn(c, T);
	}
}

# Now onto the actual code for this script...

module LongConnection;

export {
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		## Notice for when a long connection is found.
		## The `sub` field in the notice represents the number
		## of seconds the connection has currently been alive.
		LongConnection::found
	};

	## Aliasing vector of interval values as
	## "Durations"
	type Durations: vector of interval;

	## The default duration that you are locally 
	## considering a connection to be "long".  
	## After the durations run out we'll just keep tacking on 24 hours.
	const default_durations = Durations(4hr, 8hr, 12hr) &redef;

	## These are special cases for particular hosts or subnets
	## that you may want to watch for longer or shorter
	## durations than the default.
	const special_cases: table[subnet] of Durations = {} &redef;
	const monitoring_hosts: set[subnet] = {
		10.0.0.0/8
	};

}

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Conn::Info, $path="conn_long"]);
	}

function get_durations(c: connection): Durations
	{
	local check_it: Durations;
	if ( c$id$orig_h in special_cases )
		check_it = special_cases[c$id$orig_h];
	else if ( c$id$resp_h in special_cases )
		check_it = special_cases[c$id$resp_h];
	else
		check_it = default_durations;

	return check_it;
	}

function duration_to_string(duration: interval) : string
  {
    local seconds = double_to_count(interval_to_double(duration));
    local days = seconds/86400;
    local hours = (seconds - (days * 86400))/3600;
    local minutes = (seconds - (days * 86400) - (hours * 3600))/60;
    return fmt("%d day, %d hours, %d minutes", days, hours, minutes);
  }

function long_callback(c: connection, cnt: count): interval
	{
	local check_it = get_durations(c);
	local next_checkpoint :interval;

	Conn::set_conn_log_data_hack(c);
	Log::write(LongConnection::LOG, c$conn);

	local message = fmt("%s -> %s:%s remained alive for longer than %s", 
	                    c$id$orig_h, c$id$resp_h, c$id$resp_p, duration_to_string(c$duration));
	NOTICE([$note=LongConnection::found,
	        $msg=message,
	        $sub=fmt("%.2f", c$duration),
	        $conn=c]);
	
	# Keep watching if there are potentially more thresholds.
	if (cnt < |check_it|)
		next_checkpoint = check_it[cnt];
	else
		next_checkpoint = ((cnt - |check_it|) * 86400sec);
	return next_checkpoint;
	}

event connection_established(c: connection)
	{
	local check = get_durations(c);
	if(c$id$orig_h in monitoring_hosts && c$id$resp_h in monitoring_hosts) { return; }
	if ( |check| > 0 )
		{
		ConnPolling::watch(c, long_callback, 1, check[0]);
		}
	}
