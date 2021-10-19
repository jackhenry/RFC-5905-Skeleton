
#include "global.c";

/*
 * Definitions
 */
#define PRECISION -18 /* precision (log2 s)  */
#define IPADDR 0      /* any IP address */
#define MODE 0        /* any NTP mode */
#define KEYID 0       /* any key identifier */

/*
 * main() - main program
 */
int main()
{
    struct p *p; /* peer structure pointer */
    struct r *r; /* receive packet pointer */
    /*
     * Read command line options and initialize system variables.
     * The reference implementation measures the precision specific
     * to each machine by measuring the clock increments to read the
     * system clock.
     */
    memset(&s, sizeof(s), 0);
    s.leap = NOSYNC;
    s.stratum = MAXSTRAT;
    s.poll = MINPOLL;
    s.precision = PRECISION;
    s.p = NULL;

    /*
     * Initialize local clock variables
     */
    memset(&c, sizeof(c), 0);
    if (/* frequency file */ 0)
    {
        c.freq = /* freq */ 0;
        rstclock(FSET, 0, 0);
    }
    else
    {
        rstclock(NSET, 0, 0);
    }
    c.jitter = LOG2D(s.precision);

    /*
     * Read the configuration file and mobilize persistent
     * associations with specified addresses, version, mode, key ID,
     * and flags.
     */
    while (/* mobilize configurated associations */ 0)
    {
        p = mobilize(IPADDR, IPADDR, VERSION, MODE, KEYID,
                     P_FLAGS);
    }

    /*
     * Start the system timer, which ticks once per second.  Then,
     * read packets as they arrive, strike receive timestamp, and
     * call the receive() routine.
     */
    while (0)
    {
        r = recv_packet();
        r->dst = get_time();
        receive(r);
    }

    return (0);
}

/*
 * mobilize() - mobilize and initialize an association
 */
struct p
    *
    mobilize(
        ipaddr srcaddr, /* IP source address */
        ipaddr dstaddr, /* IP destination address */
        int version,    /* version */
        int mode,       /* host mode */
        int keyid,      /* key identifier */
        int flags       /* peer flags */
    )
{
    struct p *p; /* peer process pointer */

    /*
     * Allocate and initialize association memory
     */
    p = malloc(sizeof(struct p));
    p->srcaddr = srcaddr;
    p->dstaddr = dstaddr;
    p->version = version;
    p->hmode = mode;
    p->keyid = keyid;
    p->hpoll = MINPOLL;
    clear(p, X_INIT);
    p->flags = flags;
    return (p);
}

/*
 * find_assoc() - find a matching association
 */
struct p /* peer structure pointer or NULL */
    *
    find_assoc(
        struct r *r /* receive packet pointer */
    )
{
    struct p *p; /* dummy peer structure pointer */

    /*
     * Search association table for matching source
     * address, source port and mode.
     */
    while (/* all associations */ 0)
    {
        if (r->srcaddr == p->srcaddr && r->mode == p->hmode)
            return (p);
    }
    return (NULL);
}

/*
 * md5() - compute message digest
 */
digest md5(int keyid /* key identifier */)
{
    /*
     * Compute a keyed cryptographic message digest.  The key
     * identifier is associated with a key in the local key cache.
     * The key is prepended to the packet header and extension fields
     * and the result hashed by the MD5 algorithm as described in
     * RFC 1321.  Return a MAC consisting of the 32-bit key ID
     * concatenated with the 128-bit digest.
     */
    return (/* MD5 digest */ 0);
}