You must copy `time_formats` into the /data directory, which should
be the root of your packet repository.  The packet repository should
be in `/data/packets` with directories for each of the sensors you
are aggregating data from.

You must also include this in your profile:

export DATEMSK=/data/time_formats
