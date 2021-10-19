#include "global.c";
/*
 * A crypto-NAK packet includes the NTP header followed by a MAC
 * consisting only of the key identifier with value zero.  It tells
 * the receiver that a prior request could not be properly
 * authenticated, but the NTP header fields are correct.
 *
 * A kiss-o'-death packet is an NTP header with leap 0x3 (NOSYNC) and
 * stratum 16 (MAXSTRAT).  It tells the receiver that something
 * drastic has happened, as revealed by the kiss code in the refid
 * field.  The NTP header fields may or may not be correct.
 */

/*
 * Peer process parameters and constants
 */
#define SGATE 3     /* spike gate (clock filter */
#define BDELAY .004 /* broadcast delay (s) */

/*
 * Dispatch codes
 */
#define ERR -1  /* error */
#define DSCRD 0 /* discard packet */
#define PROC 1  /* process packet */
#define BCST 2  /* broadcast packet */
#define FXMIT 3 /* client packet */
#define MANY 4  /* manycast packet */
#define NEWPS 5 /* new symmetric passive client */
#define NEWBC 6 /* new broadcast client */

/*
 * Dispatch matrix
 *                active  passv  client server bcast */
int table[7][5] = {
    /* nopeer  */ {NEWPS, DSCRD, FXMIT, MANY, NEWBC},
    /* active  */ {PROC, PROC, DSCRD, DSCRD, DSCRD},
    /* passv   */ {PROC, ERR, DSCRD, DSCRD, DSCRD},
    /* client  */ {DSCRD, DSCRD, DSCRD, PROC, DSCRD},
    /* server  */ {DSCRD, DSCRD, DSCRD, DSCRD, DSCRD},
    /* bcast   */ {DSCRD, DSCRD, DSCRD, DSCRD, DSCRD},
    /* bclient */ {DSCRD, DSCRD, DSCRD, DSCRD, PROC}};

/*
 * Miscellaneous macroni
 *
 * This macro defines the authentication state.  If x is 0,
 * authentication is optional; otherwise, it is required.
 */
#define AUTH(x, y) ((x) ? (y) == A_OK : (y) == A_OK || (y) == A_NONE)

/*
 * These are used by the clear() routine
 */
#define BEGIN_CLEAR(p) ((char *)&((p)->begin_clear))
#define END_CLEAR(p) ((char *)&((p)->end_clear))
#define LEN_CLEAR (END_CLEAR((struct p *)0) - \
                   BEGIN_CLEAR((struct p *)0))

/*
 * A.5.1 receive()
 */

/*
 * receive() - receive packet and decode modes
 */
void receive(struct r *r /* receive packet pointer */)
{
    struct p *p; /* peer structure pointer */
    int auth;    /* authentication code */
    int has_mac; /* size of MAC */
    int synch;   /* synchronized switch */

    /*
     * Check access control lists.  The intent here is to implement
     * a whitelist of those IP addresses specifically accepted
     * and/or a blacklist of those IP addresses specifically
     * rejected.  There could be different lists for authenticated
     * clients and unauthenticated clients.
     */
    if (!access(r))
        return; /* access denied */

    /*
     * The version must not be in the future.  Format checks include
     * packet length, MAC length and extension field lengths, if
     * present.
     */
    if (r->version > VERSION /* or format error */)
        return; /* format error */

    /*
     * Authentication is conditioned by two switches that can be
     * specified on a per-client basis.
     *
     * P_NOPEER     do not mobilize an association unless
     *              authenticated.
     * P_NOTRUST    do not allow access unless authenticated
     *              (implies P_NOPEER).
     *
     * There are four outcomes:
     *
     * A_NONE       the packet has no MAC.
     * A_OK         the packet has a MAC and authentication
     *               succeeds.
     * A_ERROR      the packet has a MAC and authentication fails.
     * A_CRYPTO     crypto-NAK.  The MAC has four octets only.
     *
     * Note: The AUTH (x, y) macro is used to filter outcomes.  If x
     * is zero, acceptable outcomes of y are NONE and OK.  If x is
     * one, the only acceptable outcome of y is OK.
     */

    has_mac = /* length of MAC field */ 0;
    if (has_mac == 0)
    {
        auth = A_NONE; /* not required */
    }
    else if (has_mac == 4)
    {
        auth = A_CRYPTO; /* crypto-NAK */
    }
    else
    {
        if (r->mac != md5(r->keyid))
            auth = A_ERROR; /* auth error */
        else
            auth = A_OK; /* auth OK */
    }

    /*
     * Find association and dispatch code.  If there is no
     * association to match, the value of p->hmode is assumed NULL.
     */
    p = find_assoc(r);
    switch (table[(unsigned int)(p->hmode)][(unsigned int)(r->mode)])
    {
    /*
     * Client packet and no association.  Send server reply without
     * saving state.
     */
    case FXMIT:
        /*
         * If unicast destination address, send server packet.
         * If authentication fails, send a crypto-NAK packet.
         */

        /* not multicast dstaddr */
        if (0)
        {
            if (AUTH(p->flags & P_NOTRUST, auth))
                fast_xmit(r, M_SERV, auth);
            else if (auth == A_ERROR)
                fast_xmit(r, M_SERV, A_CRYPTO);
            return; /* M_SERV packet sent */
        }

        /*
         * This must be manycast.  Do not respond if we are not
         * synchronized or if our stratum is above the
         * manycaster.
         */
        if (s.leap == NOSYNC || s.stratum > r->stratum)
            return;

        /*
         * Respond only if authentication is OK.  Note that the
         * unicast address is used, not the multicast.
         */
        if (AUTH(p->flags & P_NOTRUST, auth))
            fast_xmit(r, M_SERV, auth);
        return;

    /*
     * New manycast client ephemeral association.  It is mobilized
     * in the same version as in the packet.  If authentication
     * fails, ignore the packet.  Verify the server packet by
     * comparing the r->org timestamp in the packet with the p->xmt
     * timestamp in the multicast client association.  If they
     * match, the server packet is authentic.  Details omitted.
     */
    case MANY:
        if (!AUTH(p->flags & (P_NOTRUST | P_NOPEER), auth))
            return; /* authentication error */

        p = mobilize(r->srcaddr, r->dstaddr, r->version, M_CLNT,
                     r->keyid, P_EPHEM);
        break;

    /*
     * New symmetric passive association.  It is mobilized in the
     * same version as in the packet.  If authentication fails,
     * send a crypto-NAK packet.  If restrict no-moblize, send a
     * symmetric active packet instead.
     */
    case NEWPS:
        if (!AUTH(p->flags & P_NOTRUST, auth))
        {
            if (auth == A_ERROR)
                fast_xmit(r, M_SACT, A_CRYPTO);
            return; /* crypto-NAK packet sent */
        }
        if (!AUTH(p->flags & P_NOPEER, auth))
        {
            fast_xmit(r, M_SACT, auth);
            return; /* M_SACT packet sent */
        }
        p = mobilize(r->srcaddr, r->dstaddr, r->version, M_PASV,
                     r->keyid, P_EPHEM);
        break;

    /*
     * New broadcast client association.  It is mobilized in the
     * same version as in the packet.  If authentication fails,
     * ignore the packet.  Note this code does not support the
     * initial volley feature in the reference implementation.
     */
    case NEWBC:
        if (!AUTH(p->flags & (P_NOTRUST | P_NOPEER), auth))
            return; /* authentication error */

        if (!(s.flags & S_BCSTENAB))
            return; /* broadcast not enabled */

        p = mobilize(r->srcaddr, r->dstaddr, r->version, M_BCLN,
                     r->keyid, P_EPHEM);
        break; /* processing continues */

    /*
     * Process packet.  Placeholdler only.
     */
    case PROC:
        break; /* processing continues */

    /*
     * Invalid mode combination.  We get here only in case of
     * ephemeral associations, so the correct action is simply to
     * toss it.
     */
    case ERR:
        clear(p, X_ERROR);
        return; /* invalid mode combination */

    /*
     * No match; just discard the packet.
     */
    case DSCRD:
        return; /* orphan abandoned */
    }

    /*
     * Next comes a rigorous schedule of timestamp checking.  If the
     * transmit timestamp is zero, the server is horribly broken.
     */
    if (r->xmt == 0)
        return; /* invalid timestamp */

    /*
     * If the transmit timestamp duplicates a previous one, the
     * packet is a replay.
     */
    if (r->xmt == p->xmt)
        return; /* duplicate packet */

    /*
     * If this is a broadcast mode packet, skip further checking.
     * If the origin timestamp is zero, the sender has not yet heard
     * from us.  Otherwise, if the origin timestamp does not match
     * the transmit timestamp, the packet is bogus.
     */
    synch = TRUE;
    if (r->mode != M_BCST)
    {
        if (r->org == 0)
            synch = FALSE; /* unsynchronized */

        else if (r->org != p->xmt)
            synch = FALSE; /* bogus packet */
    }

    /*
     * Update the origin and destination timestamps.  If
     * unsynchronized or bogus, abandon ship.
     */
    p->org = r->xmt;
    p->rec = r->dst;
    if (!synch)
        return; /* unsynch */

    /*
     * The timestamps are valid and the receive packet matches the
     * last one sent.  If the packet is a crypto-NAK, the server
     * might have just changed keys.  We demobilize the association
     * and wait for better times.
     */
    if (auth == A_CRYPTO)
    {
        clear(p, X_CRYPTO);
        return; /* crypto-NAK */
    }

    /*
     * If the association is authenticated, the key ID is nonzero
     * and received packets must be authenticated.  This is designed
     * to avoid a bait-and-switch attack, which was possible in past
     * versions.
     */
    if (!AUTH(p->keyid || (p->flags & P_NOTRUST), auth))
        return; /* bad auth */
    /*
     * Everything possible has been done to validate the timestamps
     * and prevent bad guys from disrupting the protocol or
     * injecting bogus data.  Earn some revenue.
     */
    packet(p, r);
}

/*
 * packet() - process packet and compute offset, delay, and
 * dispersion.
 */
void packet(
    struct p *p, /* peer structure pointer */
    struct r *r  /* receive packet pointer */
)
{
    double offset; /* sample offsset */
    double delay;  /* sample delay */
    double disp;   /* sample dispersion */

    /*
     * By golly the packet is valid.  Light up the remaining header
     * fields.  Note that we map stratum 0 (unspecified) to MAXSTRAT
     * to make stratum comparisons simpler and to provide a natural
     * interface for radio clock drivers that operate for
     *  convenience at stratum 0.
     */
    p->leap = r->leap;
    if (r->stratum == 0)
        p->stratum = MAXSTRAT;
    else
        p->stratum = r->stratum;
    p->pmode = r->mode;
    p->ppoll = r->poll;
    p->rootdelay = FP2D(r->rootdelay);
    p->rootdisp = FP2D(r->rootdisp);
    p->refid = r->refid;
    p->reftime = r->reftime;

    /*
     * Verify the server is synchronized with valid stratum and
     * reference time not later than the transmit time.
     */
    if (p->leap == NOSYNC || p->stratum >= MAXSTRAT)
        return; /* unsynchronized */

    /*
     * Verify valid root distance.
     */
    if (r->rootdelay / 2 + r->rootdisp >= MAXDISP || p->reftime > r->xmt)
        return; /* invalid header values */

    poll_update(p, p->hpoll);
    p->reach |= 1;

    /*
     * Calculate offset, delay and dispersion, then pass to the
     * clock filter.  Note carefully the implied processing.  The
     * first-order difference is done directly in 64-bit arithmetic,
     * then the result is converted to floating double.  All further
     * processing is in floating-double arithmetic with rounding
     * done by the hardware.  This is necessary in order to avoid
     * overflow and preserve precision.
     *
     * The delay calculation is a special case.  In cases where the
     * server and client clocks are running at different rates and
     * with very fast networks, the delay can appear negative.  In
     * order to avoid violating the Principle of Least Astonishment,
     * the delay is clamped not less than the system precision.
     */
    if (p->pmode == M_BCST)
    {
        offset = LFP2D(r->xmt - r->dst);
        delay = BDELAY;
        disp = LOG2D(r->precision) + LOG2D(s.precision) + PHI * 2 * BDELAY;
    }
    else
    {
        offset = (LFP2D(r->rec - r->org) + LFP2D(r->dst - r->xmt)) / 2;
        delay = max(LFP2D(r->dst - r->org) - LFP2D(r->rec - r->xmt), LOG2D(s.precision));
        disp = LOG2D(r->precision) + LOG2D(s.precision) + PHI * LFP2D(r->dst - r->org);
    }
    clock_filter(p, offset, delay, disp);
}

/*
 * clock_filter(p, offset, delay, dispersion) - select the best from the
 * latest eight delay/offset samples.
 */
void clock_filter(
    struct p *p,   /* peer structure pointer */
    double offset, /* clock offset */
    double delay,  /* roundtrip delay */
    double disp    /* dispersion */
)
{
    struct f f[NSTAGE]; /* sorted list */
    double dtemp;
    int i;

    /*
     * The clock filter contents consist of eight tuples (offset,
     * delay, dispersion, time).  Shift each tuple to the left,
     * discarding the leftmost one.  As each tuple is shifted,
     * increase the dispersion since the last filter update.  At the
     * same time, copy each tuple to a temporary list.  After this,
     * place the (offset, delay, disp, time) in the vacated
     * rightmost tuple.
     */
    for (i = 1; i < NSTAGE; i++)
    {
        p->f[i] = p->f[i - 1];
        p->f[i].disp += PHI * (c.t - p->t);
        f[i] = p->f[i];
    }
    p->f[0].t = c.t;
    p->f[0].offset = offset;
    p->f[0].delay = delay;
    p->f[0].disp = disp;
    f[0] = p->f[0];

    /*
     * Sort the temporary list of tuples by increasing f[].delay.
     * The first entry on the sorted list represents the best
     * sample, but it might be old.
     */
    dtemp = p->offset;
    p->offset = f[0].offset;
    p->delay = f[0].delay;
    for (i = 0; i < NSTAGE; i++)
    {
        p->disp += f[i].disp / (2 ^ (i + 1));
        p->jitter += SQUARE(f[i].offset - f[0].offset);
    }
    p->jitter = max(SQRT(p->jitter), LOG2D(s.precision));

    /*
     * Prime directive: use a sample only once and never a sample
     * older than the latest one, but anything goes before first
     * synchronized.
     */
    if (f[0].t - p->t <= 0 && s.leap != NOSYNC)
        return;

    /*
     * Popcorn spike suppressor.  Compare the difference between the
     * last and current offsets to the current jitter.  If greater
     * than SGATE (3) and if the interval since the last offset is
     * less than twice the system poll interval, dump the spike.
     * Otherwise, and if not in a burst, shake out the truechimers.
     */
    if (fabs(p->offset - dtemp) > SGATE * p->jitter && (f[0].t -
                                                        p->t) < 2 * s.poll)
        return;

    p->t = f[0].t;
    if (p->burst == 0)
        clock_select();
    return;
}

/*
 * fit() - test if association p is acceptable for synchronization
 */
int fit(struct p *p /* peer structure pointer */)
{
    /*
     * A stratum error occurs if (1) the server has never been
     * synchronized, (2) the server stratum is invalid.
     */
    if (p->leap == NOSYNC || p->stratum >= MAXSTRAT)
        return (FALSE);

    /*
     * A distance error occurs if the root distance exceeds the
     * distance threshold plus an increment equal to one poll
     * interval.
     */
    if (root_dist(p) > MAXDIST + PHI * LOG2D(s.poll))
        return (FALSE);

    /*
     * A loop error occurs if the remote peer is synchronized to the
     * local peer or the remote peer is synchronized to the current
     * system peer.  Note this is the behavior for IPv4; for IPv6
     * the MD5 hash is used instead.
     */
    if (p->refid == p->dstaddr || p->refid == s.refid)
        return (FALSE);

    /*
     * An unreachable error occurs if the server is unreachable.
     */
    if (p->reach == 0)
        return (FALSE);

    return (TRUE);
}

/*
 * clear() - reinitialize for persistent association, demobilize
 * for ephemeral association.
 */
void clear(
    struct p *p, /* peer structure pointer */
    int kiss     /* kiss code */
)
{
    int i;

    /*
     * The first thing to do is return all resources to the bank.
     * Typical resources are not detailed here, but they include
     * dynamically allocated structures for keys, certificates, etc.
     * If an ephemeral association and not initialization, return
     * the association memory as well.
     */
    /* return resources */
    if (s.p == p)
        s.p = NULL;
    if (kiss != X_INIT && (p->flags & P_EPHEM))
    {
        free(p);
        return;
    }

    /*
     * Initialize the association fields for general reset.
     */
    memset(BEGIN_CLEAR(p), LEN_CLEAR, 0);
    p->leap = NOSYNC;
    p->stratum = MAXSTRAT;
    p->ppoll = MAXPOLL;
    p->hpoll = MINPOLL;
    p->disp = MAXDISP;
    p->jitter = LOG2D(s.precision);
    p->refid = kiss;
    for (i = 0; i < NSTAGE; i++)
        p->f[i].disp = MAXDISP;

    /*
     * Randomize the first poll just in case thousands of broadcast
     * clients have just been stirred up after a long absence of the
     * broadcast server.
     */
    p->outdate = p->t = c.t;
    p->nextdate = p->outdate + (random() & ((1 << MINPOLL) - 1));
}

/*
 * fast_xmit() - transmit a reply packet for receive packet r
 */
void fast_xmit(
    struct r *r, /* receive packet pointer */
    int mode,    /* association mode */
    int auth     /* authentication code */
)
{
    struct x x;

    /*
     * Initialize header and transmit timestamp.  Note that the
     * transmit version is copied from the receive version.  This is
     * for backward compatibility.
     */
    x.version = r->version;
    x.srcaddr = r->dstaddr;
    x.dstaddr = r->srcaddr;
    x.leap = s.leap;
    x.mode = mode;
    if (s.stratum == MAXSTRAT)
        x.stratum = 0;
    else
        x.stratum = s.stratum;
    x.poll = r->poll;
    x.precision = s.precision;
    x.rootdelay = D2FP(s.rootdelay);
    x.rootdisp = D2FP(s.rootdisp);
    x.refid = s.refid;
    x.reftime = s.reftime;
    x.org = r->xmt;
    x.rec = r->dst;
    x.xmt = get_time();

    /*
     * If the authentication code is A.NONE, include only the
     * header; if A.CRYPTO, send a crypto-NAK; if A.OK, send a valid
     * MAC.  Use the key ID in the received packet and the key in
     * the local key cache.
     */
    if (auth != A_NONE)
    {
        if (auth == A_CRYPTO)
        {
            x.keyid = 0;
        }
        else
        {
            x.keyid = r->keyid;
            x.dgst = md5(x.keyid);
        }
    }
    xmit_packet(&x);
}

/*
 * access() - determine access restrictions
 */
int access(struct r *r /* receive packet pointer */)
{
    /*
     * The access control list is an ordered set of tuples
     * consisting of an address, mask, and restrict word containing
     * defined bits.  The list is searched for the first match on
     * the source address (r->srcaddr) and the associated restrict
     * word is returned.
     */
    return (/* access bits */ 0);
}

/*
 * clock_select() - find the best clocks
 */
void clock_select()
{
    struct p *p, *osys;      /* peer structure pointers */
    double low, high;        /* correctness interval extents */
    int allow, found, chime; /* used by intersection algorithm */
    int n, i, j;

    /*
     * We first cull the falsetickers from the server population,
     * leaving only the truechimers.  The correctness interval for
     * association p is the interval from offset - root_dist() to
     * offset + root_dist().  The object of the game is to find a
     * majority clique; that is, an intersection of correctness
     * intervals numbering more than half the server population.
     *
     * First, construct the chime list of tuples (p, type, edge) as
     * shown below, then sort the list by edge from lowest to
     * highest.
     */
    osys = s.p;
    s.p = NULL;
    n = 0;
    while (fit(p))
    {
        s.m[n].p = p;
        s.m[n].type = +1;
        s.m[n].edge = p->offset + root_dist(p);
        n++;
        s.m[n].p = p;
        s.m[n].type = 0;
        s.m[n].edge = p->offset;
        n++;
        s.m[n].p = p;
        s.m[n].type = -1;
        s.m[n].edge = p->offset - root_dist(p);
        n++;
    }

    /*
     * Find the largest contiguous intersection of correctness
     * intervals.  Allow is the number of allowed falsetickers;
     * found is the number of midpoints.  Note that the edge values
     * are limited to the range +-(2 ^ 30) < +-2e9 by the timestamp
     * calculations.
     */
    low = 2e9;
    high = -2e9;
    for (allow = 0; 2 * allow < n; allow++)
    {

        /*
         * Scan the chime list from lowest to highest to find
         * the lower endpoint.
         */
        found = 0;
        chime = 0;
        for (i = 0; i < n; i++)
        {
            chime -= s.m[i].type;
            if (chime >= n - found)
            {
                low = s.m[i].edge;
                break;
            }
            if (s.m[i].type == 0)
                found++;
        }

        /*
         * Scan the chime list from highest to lowest to find
         * the upper endpoint.
         */
        chime = 0;
        for (i = n - 1; i >= 0; i--)
        {
            chime += s.m[i].type;
            if (chime >= n - found)
            {
                high = s.m[i].edge;
                break;
            }
            if (s.m[i].type == 0)
                found++;
        }
        /*
         * If the number of midpoints is greater than the number
         * of allowed falsetickers, the intersection contains at
         * least one truechimer with no midpoint.  If so,
         * increment the number of allowed falsetickers and go
         * around again.  If not and the intersection is
         * non-empty, declare success.
         */
        if (found > allow)
            continue;

        if (high > low)
            break;
    }

    /*
     * Clustering algorithm.  Construct a list of survivors (p,
     * metric) from the chime list, where metric is dominated first
     * by stratum and then by root distance.  All other things being
     * equal, this is the order of preference.
     */
    s.n = 0;
    for (i = 0; i < n; i++)
    {
        if (s.m[i].edge < low || s.m[i].edge > high)
            continue;

        p = s.m[i].p;
        s.v[n].p = p;
        s.v[n].metric = MAXDIST * p->stratum + root_dist(p);
        s.n++;
    }

    /*
     * There must be at least NSANE survivors to satisfy the
     * correctness assertions.  Ordinarily, the Byzantine criteria
     * require four survivors, but for the demonstration here, one
     * is acceptable.
     */
    if (s.n < NSANE)
        return;

    /*
     * For each association p in turn, calculate the selection
     * jitter p->sjitter as the square root of the sum of squares
     * (p->offset - q->offset) over all q associations.  The idea is
     * to repeatedly discard the survivor with maximum selection
     * jitter until a termination condition is met.
     */
    while (1)
    {
        struct p *p, *q, *qmax; /* peer structure pointers */
        double max, min, dtemp;

        max = -2e9;
        min = 2e9;
        for (i = 0; i < s.n; i++)
        {
            p = s.v[i].p;
            if (p->jitter < min)
                min = p->jitter;
            dtemp = 0;
            for (j = 0; j < n; j++)
            {
                q = s.v[j].p;
                dtemp += SQUARE(p->offset - q->offset);
            }
            dtemp = SQRT(dtemp);
            if (dtemp > max)
            {
                max = dtemp;
                qmax = q;
            }
        }

        /*
         * If the maximum selection jitter is less than the
         * minimum peer jitter, then tossing out more survivors
         * will not lower the minimum peer jitter, so we might
         * as well stop.  To make sure a few survivors are left
         * for the clustering algorithm to chew on, we also stop
         * if the number of survivors is less than or equal to
         * NMIN (3).
         */
        if (max < min || n <= NMIN)
            break;

        /*
         * Delete survivor qmax from the list and go around
         * again.
         */
        s.n--;
    }

    /*
     * Pick the best clock.  If the old system peer is on the list
     * and at the same stratum as the first survivor on the list,
     * then don't do a clock hop.  Otherwise, select the first
     * survivor on the list as the new system peer.
     */
    if (osys->stratum == s.v[0].p->stratum)
        s.p = osys;
    else
        s.p = s.v[0].p;
    clock_update(s.p);
}

/*
 * root_dist() - calculate root distance
 */
double
root_dist(struct p *p /* peer structure pointer */)
{

    /*
     * The root synchronization distance is the maximum error due to
     * all causes of the local clock relative to the primary server.
     * It is defined as half the total delay plus total dispersion
     * plus peer jitter.
     */
    return (max(MINDISP, p->rootdelay + p->delay) / 2 +
            p->rootdisp + p->disp + PHI * (c.t - p->t) + p->jitter);
}

/*
 * accept() - test if association p is acceptable for synchronization
 */
int accept(struct p *p /* peer structure pointer */)
{
    /*
     * A stratum error occurs if (1) the server has never been
     * synchronized, (2) the server stratum is invalid.
     */
    if (p->leap == NOSYNC || p->stratum >= MAXSTRAT)
        return (FALSE);

    /*
     * A distance error occurs if the root distance exceeds the
     * distance threshold plus an increment equal to one poll
     * interval.
     */
    if (root_dist(p) > MAXDIST + PHI * LOG2D(s.poll))
        return (FALSE);

    /*
     * A loop error occurs if the remote peer is synchronized to the
     * local peer or the remote peer is synchronized to the current
     * system peer.  Note this is the behavior for IPv4; for IPv6
     * the MD5 hash is used instead.
     */
    if (p->refid == p->dstaddr || p->refid == s.refid)
        return (FALSE);

    /*
     * An unreachable error occurs if the server is unreachable.
     */
    if (p->reach == 0)
        return (FALSE);

    return (TRUE);
}

/*
 * clock_update() - update the system clock
 */
void clock_update(struct p *p /* peer structure pointer */)
{
    double dtemp;

    /*
     * If this is an old update, for instance, as the result of a
     * system peer change, avoid it.  We never use an old sample or
     * the same sample twice.
     */
    if (s.t >= p->t)
        return;

    /*
     * Combine the survivor offsets and update the system clock; the
     * local_clock() routine will tell us the good or bad news.
     */
    s.t = p->t;
    clock_combine();
    switch (local_clock(p, s.offset))
    {
    /*
     * The offset is too large and probably bogus.  Complain to the
     * system log and order the operator to set the clock manually
     * within PANIC range.  The reference implementation includes a
     * command line option to disable this check and to change the
     * panic threshold from the default 1000 s as required.
     */
    case PANIC:
        exit(0);

    /*
     * The offset is more than the step threshold (0.125 s by
     * default).  After a step, all associations now have
     * inconsistent time values, so they are reset and started
     * fresh.  The step threshold can be changed in the reference
     * implementation in order to lessen the chance the clock might
     * be stepped backwards.  However, there may be serious
     * consequences, as noted in the white papers at the NTP project
     * site.
     */
    case STEP:
        while (/* all associations */ 0)
            clear(p, X_STEP);
        s.stratum = MAXSTRAT;
        s.poll = MINPOLL;
        break;

    /*
     * The offset was less than the step threshold, which is the
     * normal case.  Update the system variables from the peer
     * variables.  The lower clamp on the dispersion increase is to
     * avoid timing loops and clockhopping when highly precise
     * sources are in play.  The clamp can be changed from the
     * default .01 s in the reference implementation.
     */
    case SLEW:
        s.leap = p->leap;
        s.stratum = p->stratum + 1;
        s.refid = p->refid;
        s.reftime = p->reftime;
        s.rootdelay = p->rootdelay + p->delay;
        dtemp = SQRT(SQUARE(p->jitter) + SQUARE(s.jitter));
        dtemp += max(p->disp + PHI * (c.t - p->t) +
                         fabs(p->offset),
                     MINDISP);
        s.rootdisp = p->rootdisp + dtemp;
        break;
    /*
     * Some samples are discarded while, for instance, a direct
     * frequency measurement is being made.
     */
    case IGNORE:
        break;
    }
}

/*
 * clock_combine() - combine offsets
 */
void clock_combine()
{
    struct p *p; /* peer structure pointer */
    double x, y, z, w;
    int i;

    /*
     * Combine the offsets of the clustering algorithm survivors
     * using a weighted average with weight determined by the root
     * distance.  Compute the selection jitter as the weighted RMS
     * difference between the first survivor and the remaining
     * survivors.  In some cases, the inherent clock jitter can be
     * reduced by not using this algorithm, especially when frequent
     * clockhopping is involved.  The reference implementation can
     * be configured to avoid this algorithm by designating a
     * preferred peer.
     */
    y = z = w = 0;
    for (i = 0; s.v[i].p != NULL; i++)
    {
        p = s.v[i].p;
        x = root_dist(p);
        y += 1 / x;
        z += p->offset / x;
        w += SQUARE(p->offset - s.v[0].p->offset) / x;
    }
    s.offset = z / y;
    s.jitter = SQRT(w / y);
}

/*
 * Clock discipline parameters and constants
 */
#define STEPT .128      /* step threshold (s) */
#define WATCH 900       /* stepout threshold (s) */
#define PANICT 1000     /* panic threshold (s) */
#define PLL 65536       /* PLL loop gain */
#define FLL MAXPOLL + 1 /* FLL loop gain */
#define AVG 4           /* parameter averaging constant */
#define ALLAN 1500      /* compromise Allan intercept (s) */
#define LIMIT 30        /* poll-adjust threshold */
#define MAXFREQ 500e-6  /* frequency tolerance (500 ppm) */
#define PGATE 4         /* poll-adjust gate */

/*
 * local_clock() - discipline the local clock
 */
int /* return code */
local_clock(
    struct p *p,  /* peer structure pointer */
    double offset /* clock offset from combine() */
)
{
    int state;   /* clock discipline state */
    double freq; /* frequency */
    double mu;   /* interval since last update */
    int rval;
    double etemp, dtemp;

    /*
     * If the offset is too large, give up and go home.
     */
    if (fabs(offset) > PANICT)
        return (PANIC);

    /*
     * Clock state machine transition function.  This is where the
     * action is and defines how the system reacts to large time
     * and frequency errors.  There are two main regimes: when the
     * offset exceeds the step threshold and when it does not.
     */
    rval = SLEW;
    mu = p->t - s.t;
    freq = 0;
    if (fabs(offset) > STEPT)
    {
        switch (c.state)
        {
        /*
         * In S_SYNC state, we ignore the first outlier and
         * switch to S_SPIK state.
         */
        case SYNC:
            state = SPIK;
            return (rval);

        /*
         * In S_FREQ state, we ignore outliers and inliers.  At
         * the first outlier after the stepout threshold,
         * compute the apparent frequency correction and step
         * the time.
         */
        case FREQ:
            if (mu < WATCH)
                return (IGNORE);

            freq = (offset - c.offset) / mu;
            /* fall through to S_SPIK */

        /*
         * In S_SPIK state, we ignore succeeding outliers until
         * either an inlier is found or the stepout threshold is
         * exceeded.
         */
        case SPIK:
            if (mu < WATCH)
                return (IGNORE);

            /* fall through to default */

        /*
         * We get here by default in S_NSET and S_FSET states
         * and from above in S_FREQ state.  Step the time and
         * clamp down the poll interval.
         *
         * In S_NSET state, an initial frequency correction is
         * not available, usually because the frequency file has
         * not yet been written.  Since the time is outside the
         * capture range, the clock is stepped.  The frequency
         * will be set directly following the stepout interval.
         *
         * In S_FSET state, the initial frequency has been set
         * from the frequency file.  Since the time is outside
         * the capture range, the clock is stepped immediately,
         * rather than after the stepout interval.  Guys get
         * nervous if it takes 17 minutes to set the clock for
         * the first time.
         *
         * In S_SPIK state, the stepout threshold has expired
         * and the phase is still above the step threshold.
         * Note that a single spike greater than the step
         * threshold is always suppressed, even at the longer
         * poll intervals.
         */
        default:

            /*
             * This is the kernel set time function, usually
             * implemented by the Unix settimeofday() system
             * call.
             */
            step_time(offset);
            c.count = 0;
            s.poll = MINPOLL;
            rval = STEP;
            if (state == NSET)
            {
                rstclock(FREQ, p->t, 0);
                return (rval);
            }
            break;
        }
        rstclock(SYNC, p->t, 0);
    }
    else
    {

        /*
         * Compute the clock jitter as the RMS of exponentially
         * weighted offset differences.  This is used by the
         * poll-adjust code.
         */
        etemp = SQUARE(c.jitter);
        dtemp = SQUARE(max(fabs(offset - c.last),
                           LOG2D(s.precision)));
        c.jitter = SQRT(etemp + (dtemp - etemp) / AVG);
        switch (c.state)
        {

        /*
         * In S_NSET state, this is the first update received
         * and the frequency has not been initialized.  The
         * first thing to do is directly measure the oscillator
         * frequency.
         */
        case NSET:
            rstclock(FREQ, p->t, offset);
            return (IGNORE);

        /*
         * In S_FSET state, this is the first update and the
         * frequency has been initialized.  Adjust the phase,
         * but don't adjust the frequency until the next update.
         */
        case FSET:
            rstclock(SYNC, p->t, offset);
            break;

        /*
         * In S_FREQ state, ignore updates until the stepout
         * threshold.  After that, correct the phase and
         * frequency and switch to S_SYNC state.
         */
        case FREQ:
            if (c.t - s.t < WATCH)
                return (IGNORE);

            freq = (offset - c.offset) / mu;
            break;

        /*
         * We get here by default in S_SYNC and S_SPIK states.
         * Here we compute the frequency update due to PLL and
         * FLL contributions.
         */
        default:

            /*
             * The FLL and PLL frequency gain constants
             * depending on the poll interval and Allan
             * intercept.  The FLL is not used below one
             * half the Allan intercept.  Above that the
             * loop gain increases in steps to 1 / AVG.
             */
            if (LOG2D(s.poll) > ALLAN / 2)
            {
                etemp = FLL - s.poll;
                if (etemp < AVG)
                    etemp = AVG;
                freq += (offset - c.offset) / (max(mu,
                                                   ALLAN) *
                                               etemp);
            }

            /*
             * For the PLL the integration interval
             * (numerator) is the minimum of the update
             * interval and poll interval.  This allows
             * oversampling, but not undersampling.
             */
            etemp = min(mu, LOG2D(s.poll));
            dtemp = 4 * PLL * LOG2D(s.poll);
            freq += offset * etemp / (dtemp * dtemp);
            rstclock(SYNC, p->t, offset);
            break;
        }
    }

    /*
     * Calculate the new frequency and frequency stability (wander).
     * Compute the clock wander as the RMS of exponentially weighted
     * frequency differences.  This is not used directly, but can,
     * along with the jitter, be a highly useful monitoring and
     * debugging tool.
     */
    freq += c.freq;
    c.freq = max(min(MAXFREQ, freq), -MAXFREQ);
    etemp = SQUARE(c.wander);
    dtemp = SQUARE(freq);
    c.wander = SQRT(etemp + (dtemp - etemp) / AVG);

    /*
     * Here we adjust the poll interval by comparing the current
     * offset with the clock jitter.  If the offset is less than the
     * clock jitter times a constant, then the averaging interval is
     * increased; otherwise, it is decreased.  A bit of hysteresis
     * helps calm the dance.  Works best using burst mode.
     */
    if (fabs(c.offset) < PGATE * c.jitter)
    {
        c.count += s.poll;
        if (c.count > LIMIT)
        {
            c.count = LIMIT;
            if (s.poll < MAXPOLL)
            {
                c.count = 0;
                s.poll++;
            }
        }
    }
    else
    {
        c.count -= s.poll << 1;
        if (c.count < -LIMIT)
        {
            c.count = -LIMIT;
            if (s.poll > MINPOLL)
            {
                c.count = 0;
                s.poll--;
            }
        }
    }
    return (rval);
}

/*
 * rstclock() - clock state machine
 */
void rstclock(
    int state,     /* new state */
    double offset, /* new offset */
    double t       /* new update time */
)
{
    /*
     * Enter new state and set state variables.  Note, we use the
     * time of the last clock filter sample, which must be earlier
     * than the current time.
     */
    c.state = state;
    c.last = c.offset = offset;
    s.t = t;
}

/*
 * clock_adjust() - runs at one-second intervals
 */
void clock_adjust()
{
    double dtemp;

    /*
     * Update the process time c.t.  Also increase the dispersion
     * since the last update.  In contrast to NTPv3, NTPv4 does not
     * declare unsynchronized after one day, since the dispersion
     * threshold serves this function.  When the dispersion exceeds
     * MAXDIST (1 s), the server is considered unfit for
     * synchronization.
     */
    c.t++;
    s.rootdisp += PHI;

    /*
     * Implement the phase and frequency adjustments.  The gain
     * factor (denominator) is not allowed to increase beyond the
     * Allan intercept.  It doesn't make sense to average phase
     * noise beyond this point and it helps to damp residual offset
     * at the longer poll intervals.
     */
    dtemp = c.offset / (PLL * min(LOG2D(s.poll), ALLAN));
    c.offset -= dtemp;

    /*
     * This is the kernel adjust time function, usually implemented
     * by the Unix adjtime() system call.
     */
    adjust_time(c.freq + dtemp);

    /*
     * Peer timer.  Call the poll() routine when the poll timer
     * expires.
     */
    while (/* all associations */ 0)
    {
        struct p *p; /* dummy peer structure pointer */

        if (c.t >= p->nextdate)
            poll(p);
    }

    /*
     * Once per hour, write the clock frequency to a file.
     */
    /*
     * if (c.t % 3600 == 3599)
     *   write c.freq to file
     */
}

/*
 * Poll process parameters and constants
 */
#define UNREACH 12 /* unreach counter threshold */
#define BCOUNT 8   /* packets in a burst */
#define BTIME 2    /* burst interval (s) */

/*
 * poll() - determine when to send a packet for association p->
 */
void poll(struct p *p /* peer structure pointer */)
{
    int hpoll;
    int oreach;

    /*
     * This routine is called when the current time c.t catches up
     * to the next poll time p->nextdate.  The value p->outdate is
     * the last time this routine was executed.  The poll_update()
     * routine determines the next execution time p->nextdate.
     *
     * If broadcasting, just do it, but only if we are synchronized.
     */
    hpoll = p->hpoll;
    if (p->hmode == M_BCST)
    {
        p->outdate = c.t;
        if (s.p != NULL)
            peer_xmit(p);
        poll_update(p, hpoll);
        return;
    }

    /*
     * If manycasting, start with ttl = 1.  The ttl is increased by
     * one for each poll until MAXCLOCK servers have been found or
     * ttl reaches TTLMAX.  If reaching MAXCLOCK, stop polling until
     * the number of servers falls below MINCLOCK, then start all
     * over.
     */
    if (p->hmode == M_CLNT && p->flags & P_MANY)
    {
        p->outdate = c.t;
        if (p->unreach > BEACON)
        {
            p->unreach = 0;
            p->ttl = 1;
            peer_xmit(p);
        }
        else if (s.n < MINCLOCK)
        {
            if (p->ttl < TTLMAX)
                p->ttl++;
            peer_xmit(p);
        }
        p->unreach++;
        poll_update(p, hpoll);
        return;
    }
    if (p->burst == 0)
    {

        /*
         * We are not in a burst.  Shift the reachability
         * register to the left.  Hopefully, some time before
         * the next poll a packet will arrive and set the
         * rightmost bit.
         */
        oreach = p->reach;
        p->outdate = c.t;
        p->reach = p->reach << 1;
        if (!(p->reach & 0x7))
            clock_filter(p, 0, 0, MAXDISP);
        if (!p->reach)
        {

            /*
             * The server is unreachable, so bump the
             * unreach counter.  If the unreach threshold
             * has been reached, double the poll interval
             * to minimize wasted network traffic.  Send a
             * burst only if enabled and the unreach
             * threshold has not been reached.
             */
            if (p->flags & P_IBURST && p->unreach == 0)
            {
                p->burst = BCOUNT;
            }
            else if (p->unreach < UNREACH)
                p->unreach++;
            else
                hpoll++;
            p->unreach++;
        }
        else
        {

            /*
             * The server is reachable.  Set the poll
             * interval to the system poll interval.  Send a
             * burst only if enabled and the peer is fit.
             */
            p->unreach = 0;
            hpoll = s.poll;
            if (p->flags & P_BURST && fit(p))
                p->burst = BCOUNT;
        }
    }
    else
    {
        /*
         * If in a burst, count it down.  When the reply comes
         * back the clock_filter() routine will call
         * clock_select() to process the results of the burst.
         */
        p->burst--;
    }
    /*
     * Do not transmit if in broadcast client mode.
     */
    if (p->hmode != M_BCLN)
        peer_xmit(p);
    poll_update(p, hpoll);
}

/*
 * poll_update() - update the poll interval for association p
 *
 * Note: This routine is called by both the packet() and poll() routine.
 * Since the packet() routine is executed when a network packet arrives
 * and the poll() routine is executed as the result of timeout, a
 * potential race can occur, possibly causing an incorrect interval for
 * the next poll.  This is considered so unlikely as to be negligible.
 */
void poll_update(
    struct p *p, /* peer structure pointer */
    int poll     /* poll interval (log2 s) */
)
{
    /*
     * This routine is called by both the poll() and packet()
     * routines to determine the next poll time.  If within a burst
     * the poll interval is two seconds.  Otherwise, it is the
     * minimum of the host poll interval and peer poll interval, but
     * not greater than MAXPOLL and not less than MINPOLL.  The
     * design ensures that a longer interval can be preempted by a
     * shorter one if required for rapid response.
     */
    p->hpoll = max(min(MAXPOLL, poll), MINPOLL);
    if (p->burst > 0)
    {
        if (p->nextdate != c.t)
            return;
        else
            p->nextdate += BTIME;
    }
    else
    {
        /*
         * While not shown here, the reference implementation
         * randomizes the poll interval by a small factor.
         */
        p->nextdate = p->outdate + (1 << max(min(p->ppoll,
                                                 p->hpoll),
                                             MINPOLL));
    }

    /*
     * It might happen that the due time has already passed.  If so,
     * make it one second in the future.
     */
    if (p->nextdate <= c.t)
        p->nextdate = c.t + 1;
}

/*
 * transmit() - transmit a packet for association p
 */
void peer_xmit(struct p *p /* peer structure pointer */)
{
    struct x x; /* transmit packet */

    /*
     * Initialize header and transmit timestamp
     */
    x.srcaddr = p->dstaddr;
    x.dstaddr = p->srcaddr;
    x.leap = s.leap;
    x.version = p->version;
    x.mode = p->hmode;
    if (s.stratum == MAXSTRAT)
        x.stratum = 0;
    else
        x.stratum = s.stratum;
    x.poll = p->hpoll;
    x.precision = s.precision;
    x.rootdelay = D2FP(s.rootdelay);
    x.rootdisp = D2FP(s.rootdisp);
    x.refid = s.refid;
    x.reftime = s.reftime;
    x.org = p->org;
    x.rec = p->rec;
    x.xmt = get_time();
    p->xmt = x.xmt;

    /*
     * If the key ID is nonzero, send a valid MAC using the key ID
     * of the association and the key in the local key cache.  If
     * something breaks, like a missing trusted key, don't send the
     * packet; just reset the association and stop until the problem
     * is fixed.
     */
    if (p->keyid)
        if (/* p->keyid invalid */ 0)
        {
            clear(p, X_NKEY);
            return;
        }
    x.dgst = md5(p->keyid);
    xmit_packet(&x);
}
