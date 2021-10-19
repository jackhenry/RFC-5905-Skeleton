#include <math.h>     /* avoids complaints about sqrt() */
#include <sys/time.h> /* for gettimeofday() and friends */
#include <stdlib.h>   /* for malloc() and friends */
#include <string.h>   /* for memset() */

/*
 * Data types
 *
 * This program assumes the int data type is 32 bits and the long data
 * type is 64 bits.  The native data type used in most calculations is
 * floating double.  The data types used in some packet header fields
 * require conversion to and from this representation.  Some header
 * fields involve partitioning an octet, here represented by individual
 * octets.
 *
 * The 64-bit NTP timestamp format used in timestamp calculations is
 * unsigned seconds and fraction with the decimal point to the left of
 * bit 32.  The only operation permitted with these values is
 * subtraction, yielding a signed 31-bit difference.  The 32-bit NTP
 * short format used in delay and dispersion calculations is seconds and
 * fraction with the decimal point to the left of bit 16.  The only
 * operations permitted with these values are addition and
 * multiplication by a constant.
 *
 * The IPv4 address is 32 bits, while the IPv6 address is 128 bits.  The
 * message digest field is 128 bits as constructed by the MD5 algorithm.
 * The precision and poll interval fields are signed log2 seconds.
 */
typedef unsigned long long tstamp; /* NTP timestamp format */
typedef unsigned int tdist;        /* NTP short format */
typedef unsigned long ipaddr;      /* IPv4 or IPv6 address */
typedef unsigned long digest;      /* md5 digest */
typedef signed char s_char;        /* precision and poll interval (log2) */

/*
 * Timestamp conversion macroni
 */
#define FRIC 65536.                 /* 2^16 as a double */
#define D2FP(r) ((tdist)((r)*FRIC)) /* NTP short */
#define FP2D(r) ((double)(r) / FRIC)

#define FRAC 4294967296.              /* 2^32 as a double */
#define D2LFP(a) ((tstamp)((a)*FRAC)) /* NTP timestamp */
#define LFP2D(a) ((double)(a) / FRAC)
#define U2LFP(a) (((unsigned long long)((a).tv_sec + JAN_1970) << 32) + \
                  (unsigned long long)((a).tv_usec / 1e6 * FRAC))

/*
 * Arithmetic conversions
 */
#define LOG2D(a) ((a) < 0 ? 1. / (1L << -(a)) : 1L << (a)) /* poll, etc. */
#define SQUARE(x) (x * x)
#define SQRT(x) (sqrt(x))

/*
 * Global constants.  Some of these might be converted to variables
 * that can be tinkered by configuration or computed on-the-fly.  For
 * instance, the reference implementation computes PRECISION on-the-fly
 * and provides performance tuning for the defines marked with % below.
 */
#define VERSION 4   /* version number */
#define MINDISP .01 /* % minimum dispersion (s) */
#define MAXDISP 16  /* maximum dispersion (s) */
#define MAXDIST 1   /* % distance threshold (s) */
#define NOSYNC 0x3  /* leap unsync */
#define MAXSTRAT 16 /* maximum stratum (infinity metric) */
#define MINPOLL 6   /* % minimum poll interval (64 s)*/
#define MAXPOLL 17  /* % maximum poll interval (36.4 h) */
#define MINCLOCK 3  /* minimum manycast survivors */
#define MAXCLOCK 10 /* maximum manycast candidates */
#define TTLMAX 8    /* max ttl manycast */
#define BEACON 15   /* max interval between beacons */

#define PHI 15e-6 /* % frequency tolerance (15 ppm) */
#define NSTAGE 8  /* clock register stages */
#define NMAX 50   /* maximum number of peers */
#define NSANE 1   /* % minimum intersection survivors */
#define NMIN 3    /* % minimum cluster survivors */

/*
 * Global return values
 */
#define TRUE 1  /* boolean true */
#define FALSE 0 /* boolean false */

/*
 * Local clock process return codes
 */
#define IGNORE 0 /* ignore */
#define SLEW 1   /* slew adjustment */
#define STEP 2   /* step adjustment */
#define PANIC 3  /* panic - no adjustment */

/*
 * System flags
 */
#define S_FLAGS 0      /* any system flags */
#define S_BCSTENAB 0x1 /* enable broadcast client */

/*
 * Peer flags
 */
#define P_FLAGS 0      /* any peer flags */
#define P_EPHEM 0x01   /* association is ephemeral */
#define P_BURST 0x02   /* burst enable */
#define P_IBURST 0x04  /* intial burst enable */
#define P_NOTRUST 0x08 /* authenticated access */
#define P_NOPEER 0x10  /* authenticated mobilization */
#define P_MANY 0x20    /* manycast client */
/*
 * Authentication codes
 */
#define A_NONE 0   /* no authentication */
#define A_OK 1     /* authentication OK */
#define A_ERROR 2  /* authentication error */
#define A_CRYPTO 3 /* crypto-NAK */

/*
 * Association state codes
 */
#define X_INIT 0   /* initialization */
#define X_STALE 1  /* timeout */
#define X_STEP 2   /* time step */
#define X_ERROR 3  /* authentication error */
#define X_CRYPTO 4 /* crypto-NAK received */
#define X_NKEY 5   /* untrusted key */

/*
 * Protocol mode definitions
 */
#define M_RSVD 0 /* reserved */
#define M_SACT 1 /* symmetric active */
#define M_PASV 2 /* symmetric passive */
#define M_CLNT 3 /* client */
#define M_SERV 4 /* server */
#define M_BCST 5 /* broadcast server */
#define M_BCLN 6 /* broadcast client */

/*
 * Clock state definitions
 */
#define NSET 0 /* clock never set */
#define FSET 1 /* frequency set from file */
#define SPIK 2 /* spike detected */
#define FREQ 3 /* frequency mode */
#define SYNC 4 /* clock synchronized */

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) < (b) ? (b) : (a))

/*
 * A.1.2 Packet Data Structures
 *
 */

/*
 * The receive and transmit packets may contain an optional message
 * authentication code (MAC) consisting of a key identifier (keyid) and
 * message digest (mac in the receive structure and dgst in the transmit
 * structure).  NTPv4 supports optional extension fields that
 * are inserted after the header and before the MAC, but these are
 * not described here.
 *
 * Receive packet
 *
 * Note the dst timestamp is not part of the packet itself.  It is
 * captured upon arrival and returned in the receive buffer along with
 * the buffer length and data.  Note that some of the char fields are
 * packed in the actual header, but the details are omitted here.
 */
struct r
{
  ipaddr srcaddr;   /* source (remote) address */
  ipaddr dstaddr;   /* destination (local) address */
  char version;     /* version number */
  char leap;        /* leap indicator */
  char mode;        /* mode */
  char stratum;     /* stratum */
  char poll;        /* poll interval */
  s_char precision; /* precision */
  tdist rootdelay;  /* root delay */
  tdist rootdisp;   /* root dispersion */
  char refid;       /* reference ID */
  tstamp reftime;   /* reference time */
  tstamp org;       /* origin timestamp */
  tstamp rec;       /* receive timestamp */
  tstamp xmt;       /* transmit timestamp */
  int keyid;        /* key ID */
  digest mac;       /* message digest */
  tstamp dst;       /* destination timestamp */
} r;

/*
 * Transmit packet
 */
struct x
{
  ipaddr dstaddr;   /* source (local) address */
  ipaddr srcaddr;   /* destination (remote) address */
  char version;     /* version number */
  char leap;        /* leap indicator */
  char mode;        /* mode */
  char stratum;     /* stratum */
  char poll;        /* poll interval */
  s_char precision; /* precision */
  tdist rootdelay;  /* root delay */
  tdist rootdisp;   /* root dispersion */
  char refid;       /* reference ID */
  tstamp reftime;   /* reference time */
  tstamp org;       /* origin timestamp */
  tstamp rec;       /* receive timestamp */
  tstamp xmt;       /* transmit timestamp */
  int keyid;        /* key ID */
  digest dgst;      /* message digest */
} x;

/*
 * A.1.3 Association Data Structures
 */

/*
 * Filter stage structure.  Note the t member in this and other
 * structures refers to process time, not real time.  Process time
 * increments by one second for every elapsed second of real time.
 */
struct f
{
  tstamp t;      /* update time */
  double offset; /* clock ofset */
  double delay;  /* roundtrip delay */
  double disp;   /* dispersion */
} f;

/*
 * Association structure.  This is shared between the peer process
 * and poll process.
 */
struct p
{

  /*
   * Variables set by configuration
   */
  ipaddr srcaddr; /* source (remote) address */
  ipaddr dstaddr; /* destination (local) address */
  char version;   /* version number */
  char hmode;     /* host mode */
  int keyid;      /* key identifier */
  int flags;      /* option flags */

  /*
   * Variables set by received packet
   */
  char leap;            /* leap indicator */
  char pmode;           /* peer mode */
  char stratum;         /* stratum */
  char ppoll;           /* peer poll interval */
  double rootdelay;     /* root delay */
  double rootdisp;      /* root dispersion */
  char refid;           /* reference ID */
  tstamp reftime;       /* reference time */
#define begin_clear org /* beginning of clear area */
  tstamp org;           /* originate timestamp */
  tstamp rec;           /* receive timestamp */
  tstamp xmt;           /* transmit timestamp */

  /*
   * Computed data
   */
  double t;           /* update time */
  struct f f[NSTAGE]; /* clock filter */
  double offset;      /* peer offset */
  double delay;       /* peer delay */
  double disp;        /* peer dispersion */
  double jitter;      /* RMS jitter */

  /*
   * Poll process variables
   */
  char hpoll;             /* host poll interval */
  int burst;              /* burst counter */
  int reach;              /* reach register */
  int ttl;                /* ttl (manycast) */
#define end_clear unreach /* end of clear area */
  int unreach;            /* unreach counter */
  int outdate;            /* last poll time */
  int nextdate;           /* next poll time */
} p;

/*
 * A.1.4 System Data Structures
 */

/*
 * Chime list.  This is used by the intersection algorithm.
 */
struct m
{              /* m is for Marzullo */
  struct p *p; /* peer structure pointer */
  int type;    /* high +1, mid 0, low -1 */
  double edge; /* correctness interval edge */
} m;

/*
 * Survivor list.  This is used by the clustering algorithm.
 */
struct v
{
  struct p *p;   /* peer structure pointer */
  double metric; /* sort metric */
} v;

/*
 * System structure
 */
struct s
{
  tstamp t;         /* update time */
  char leap;        /* leap indicator */
  char stratum;     /* stratum */
  char poll;        /* poll interval */
  char precision;   /* precision */
  double rootdelay; /* root delay */
  double rootdisp;  /* root dispersion */
  char refid;       /* reference ID */
  tstamp reftime;   /* reference time */
  struct m m[NMAX]; /* chime list */
  struct v v[NMAX]; /* survivor list */
  struct p *p;      /* association ID */
  double offset;    /* combined offset */
  double jitter;    /* combined jitter */
  int flags;        /* option flags */
  int n;            /* number of survivors */
} s;

/*
 * A.1.5 Local Clock Data Structures
 */
struct c
{
  tstamp t;      /* update time */
  int state;     /* current state */
  double offset; /* current offset */
  double last;   /* previous offset */
  int count;     /* jiggle counter */
  double freq;   /* frequency */
  double jitter; /* RMS jitter */
  double wander; /* RMS wander */
} c;

/*
 * A.1.6 Function Prototypes
 */

/*
 * Peer process
 */
void receive(struct r *);                              /* receive packet */
void packet(struct p *, struct r *);                   /* process packet */
void clock_filter(struct p *, double, double, double); /* filter */
double root_dist(struct p *);                          /* calculate root distance */
int fit(struct p *);                                   /* determine fitness of server */
void clear(struct p *, int);                           /* clear association */
int access(struct r *);                                /* determine access restrictions */

/*
 * System process
 */
int main();                    /* main program */
void clock_select();           /* find the best clocks */
void clock_update(struct p *); /* update the system clock */
void clock_combine();          /* combine the offsets */

/*
 * Local clock process
 */
int local_clock(struct p *, double); /* clock discipline */
void rstclock(int, double, double);  /* clock state transition */

/*
 * Clock adjust process
 */
void clock_adjust(); /* one-second timer process */
/*
 * Poll process
 */
void poll(struct p *);                /* poll process */
void poll_update(struct p *, int);    /* update the poll interval */
void peer_xmit(struct p *);           /* transmit a packet */
void fast_xmit(struct r *, int, int); /* transmit a reply packet */

/*
 * Utility routines
 */
digest md5(int);                                        /* generate a message digest */
struct p *mobilize(ipaddr, ipaddr, int, int, int, int); /* mobilize */
struct p *find_assoc(struct r *);                       /* search the association table */

/*
 * Kernel interface
 */
struct r *recv_packet();      /* wait for packet */
void xmit_packet(struct x *); /* send packet */
void step_time(double);       /* step time */
void adjust_time(double);     /* adjust (slew) time */
tstamp get_time();