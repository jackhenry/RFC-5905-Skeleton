#include "global.c";
/*
 * System clock utility functions
 *
 * There are three time formats: native (Unix), NTP, and floating
 * double.  The get_time() routine returns the time in NTP long format.
 * The Unix routines expect arguments as a structure of two signed
 * 32-bit words in seconds and microseconds (timeval) or nanoseconds
 * (timespec).  The step_time() and adjust_time() routines expect signed
 * arguments in floating double.  The simplified code shown here is for
 * illustration only and has not been verified.
 */
#define JAN_1970 2208988800UL /* 1970 - 1900 in seconds */

/*
 * get_time - read system time and convert to NTP format
 */
tstamp get_time()
{
    struct timeval unix_time;
    /*
     * There are only two calls on this routine in the program.  One
     * when a packet arrives from the network and the other when a
     * packet is placed on the send queue.  Call the kernel time of
     * day routine (such as gettimeofday()) and convert to NTP
     * format.
     */
    gettimeofday(&unix_time, NULL);
    return (U2LFP(unix_time));
}

/*
 * step_time() - step system time to given offset value
 */
void step_time(
    double offset /* clock offset */
)
{
    struct timeval unix_time;
    tstamp ntp_time;

    /*
         * Convert from double to native format (signed) and add to the
         * current time.  Note the addition is done in native format to
         * avoid overflow or loss of precision.
         */
    gettimeofday(&unix_time, NULL);
    ntp_time = D2LFP(offset) + U2LFP(unix_time);
    unix_time.tv_sec = ntp_time >> 32;
    unix_time.tv_usec = (long)(((ntp_time - unix_time.tv_sec) << 32) / FRAC * 1e6);
    settimeofday(&unix_time, NULL);
}

/*
 * adjust_time() - slew system clock to given offset value
 */
void adjust_time(double offset /* clock offset */)
{
    struct timeval unix_time;
    tstamp ntp_time;
    /*
     * Convert from double to native format (signed) and add to the
     * current time.
     */
    ntp_time = D2LFP(offset);
    unix_time.tv_sec = ntp_time >> 32;
    unix_time.tv_usec = (long)(((ntp_time - unix_time.tv_sec) << 32) / FRAC * 1e6);
    adjtime(&unix_time, NULL);
}