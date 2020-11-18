#!/usr/bin/perl

##
#  quick script used to extract lines with IP addresses from a file
##

use strict;

my $ip=$1;


while ( <STDIN> ) {
    while ( s/[0-9a-f:]//i ) {
	
    }

}

sub isipv6 {
    my $string=shift;
    if ( $string =~ /^[0-9a-f:]+$/ ) {
	my $col=~ s/[^:]//g;
	my $ncol=length($col);
	if ( $ncol<2 or $ncol>7 ) {
	    return false;
	}
	if ( $string =~ /[0-9]{5}/ ) {
	    return false;
	}
    }
    return false;
}
