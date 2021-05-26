# Build a profile for the OS at a particular IP address based on protocol fields.

type hostProfile: record {
    windowSize: count;
    arrivingTTL: count;
    DFSet: bool;
    windowScaling: int;
    MSS: count;
    SACKSupport: bool;
    };


function equal(a: hostProfile, b: hostProfile): bool
{
    if(a$windowSize != b$windowSize) { return F; }
    # For the TTL: We aren't so interested in whether or not this is exactly the same.  Depending
    # on the position of the sensor, this number can vary by a couple of values in either direction.
    # However, if it varies by more than 32, we are likely looking at a different OS since starting
    # TTLs tend to be 32, 64, 128, 256.
    local aTTL: int = a$arrivingTTL;
    local bTTL: int = b$arrivingTTL;
    if(|aTTL - bTTL| > 15 ) { return F; }
    if(a$DFSet != b$DFSet) { return F; }
    if(a$windowScaling != b$windowScaling) { return F; }
    if(a$MSS != b$MSS) { return F; }
    if(a$SACKSupport != b$SACKSupport) { return F; }
    return T;
}

global mySubnets: set[subnet] = {192.168.0.0/16};
global profiles: table[addr] of hostProfile;

event connection_SYN_packet(c: connection, packet: SYN_packet)
{
    if(c$id$orig_h !in mySubnets) { return; }
    if(c$id$orig_h !in profiles) { 
        profiles[c$id$orig_h] = [
            $windowSize = packet$win_size,
            $arrivingTTL = packet$ttl,
            $DFSet = packet$DF,
            $windowScaling = packet$win_scale,
            $MSS = packet$MSS,
            $SACKSupport = packet$SACK_OK
        ];
    } else {
        local currentValues: hostProfile;
        currentValues$windowSize = packet$win_size;
        currentValues$arrivingTTL = packet$ttl;
        currentValues$DFSet = packet$DF;
        currentValues$windowScaling = packet$win_scale;
        currentValues$MSS = packet$MSS;
        currentValues$SACKSupport = packet$SACK_OK;
        if(!equal(currentValues,profiles[c$id$orig_h])) {
            print fmt("Profile mismatch for %s", c$id$orig_h);
            print currentValues;
            print profiles[c$id$orig_h];
            print "---";
        }

    }
}
