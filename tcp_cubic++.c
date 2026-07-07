// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of CUBIC TCP in
 * Sangtae Ha, Injong Rhee and Lisong Xu,
 *  "CUBIC: A New TCP-Friendly High-Speed TCP Variant"
 *  in ACM SIGOPS Operating System Review, July 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf
 *
 * CUBIC integrates a new slow start algorithm, called HyStart.
 * The details of HyStart are presented in
 *  Sangtae Ha and Injong Rhee,
 *  "Taming the Elephants: New TCP Slow Start", NCSU TechReport 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/hystart_techreport_2008.pdf
 *
 * All testing results are available from:
 * http://netsrv.csc.ncsu.edu/wiki/index.php/TCP_Testing
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <linux/mm.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

#define CUBICPP
#define CUBICPP_NODEBUG
#ifdef CUBICPP_NODEBUG
#define DP(...)
#else /* CUBICPP_NODEBUG */
bool debug __read_mostly = true;
EXPORT_SYMBOL(debug);
#define DP(fmt, ...)    if (debug) printk("%s:%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define PACING_RATE(sk)	(READ_ONCE((sk)->sk_pacing_rate) * NBBY / 1024 / 1024)
#endif /* ! CUBICPP_NODEBUG */

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
//#define CUBICPP_SHORT_THRESHOLD
#ifdef CUBICPP_SHORT_THRESHOLD
#define HYSTART_DELAY_MIN	(1000U)	/* 2.5 ms */
#else /* CUBICPP */
#define HYSTART_DELAY_MIN	(4000U)	/* 4 ms */
#endif /* ! CUBICPP */
#define HYSTART_DELAY_MAX	(16000U)	/* 16 ms */
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)
/* HyStart++ RFC9406. */
#ifdef CUBICPP
#ifdef CUBICPP_SHORT_THRESHOLD
#define HYSTART_RTT_DIVISOR_SHIFT	4
#else /* CUBICPP_SHORT_THRESHOLD */
#define HYSTART_RTT_DIVISOR_SHIFT	3
#endif /* ! CUBICPP_SHORT_THRESHOLD */
#define HYSTART_CSS_GROWTH_DIVISOR	4
#define HYSTART_CSS_ROUNDS		5
#endif /* CUBICPP */

static int fast_convergence __read_mostly = 1;
static int beta __read_mostly = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
#ifdef CUBICPP
static int gamma __read_mostly = 956;	/* = 956/1024 (BICTCP_BETA_SCALE) */
#endif /*  CUBICPP */
static int initial_ssthresh __read_mostly;
static int bic_scale __read_mostly = 41;
static int tcp_friendliness __read_mostly = 1;

static int hystart __read_mostly = 1;
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_ack_delta_us __read_mostly = 2000;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(bic_scale, int, 0444);
MODULE_PARM_DESC(bic_scale, "scale (scaled by 1024) value for bic function (bic_scale/1024)");
module_param(tcp_friendliness, int, 0644);
MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");
module_param(hystart, int, 0644);
MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hybrid slow start detection mechanisms"
		 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_ack_delta_us, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta_us, "spacing between ack's indicating train (usecs)");

/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */
	u32	bic_K;		/* time to origin point
				   from the beginning of the current epoch */
	u32	delay_min;	/* min delay (usec) */
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
#ifdef CUBICPP
	u16	unused;
	u8	sample_cnt;	/* number of samples to decide curr_rtt */
	u8	found:1,	/* the exit point is found? */
#define HYSTART_CSS_ROUND_NONE		0
#define HYSTART_CSS_ROUND_FINISH	6
		round:3,	/* 0: init, 1,2,3,4,5: CSS, 6: finish. */
#define HYSTART_OPEN		0
#define HYSTART_CONGESTED	1
		state:1,
		unused_a:2,
		pacing_workaround:1;
#endif /* CUBICPP */
#ifdef HYSTART_FULL_ROUND
	u32	end_seq;	/* end_seq of the round */
#endif /* HYSTART_FULL_ROUND */
	u32	curr_rtt;	/* the minimum rtt of current round */
#ifdef CUBICPP
#define HYSTART_INFINITY	(~0U)
	u32	bw_stamp;
	u32	bw_cnt;
	struct minmax bw;
	u32	curr_rtt_max;	/* the maximum rtt of current round */
	u32	prior_rtt;	/* the minimum rtt of previous round */
	u32	prior_rtt_max;
	u32	css_rtt;
	u32	css_rtt_max;
#endif /* CUBICPP */
#ifdef CUBICPP_X
	u32	prior_snd_una;
#endif /* CUBICPP */
};

#if ! defined(CUBICPP_NODEBUG)
static const char *tcp_state_name(u8 state)
{
#define S(name)	[TCP_CA_##name] = #name
	static const char *names[] = {
		S(Open),
		S(Disorder),
		S(CWR),
		S(Recovery),
		S(Loss),
	};
#undef S
	if (state <= sizeof(names) / sizeof(names[0]))
		return names[state];
	else
		return "unknown";
}

/* XXX: copy from tcp_input.c */
static bool
tcp_is_rack(struct sock *sk)
{
	return !! (READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_recovery) &
            TCP_RACK_LOSS_DETECTION);
}
#endif /* ! CUBICPP_NODEBUG */

static inline void bictcp_reset(struct bictcp *ca)
{
	memset(ca, 0, offsetof(struct bictcp, unused));
	ca->found = 0;
}

static inline bool hystart_is_active(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	return tcp_in_slow_start(tp) && ca->round <= HYSTART_CSS_ROUNDS;
}

static u32 hystart_max_bw(const struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	return minmax_get(&ca->bw);
}

static u32 hystart_max_bw_cwnd(const struct sock *sk, const struct rate_sample *rs)
{
	u64 cwnd;

#define BW_SCALE 24
#define BW_UNIT	(1 << BW_SCALE)
#define HYSTART_BW_WINDOW	(HYSTART_MIN_SAMPLES + 2)
#if ! defined(NBBY)
#define NBBY 8
#endif /* ! NBBY */
	cwnd = hystart_max_bw(sk);
	if ((s64)rs->rtt_us > 0)
		cwnd *= rs->rtt_us;
	else if ((s64)((struct bictcp *)inet_csk_ca(sk))->delay_min > 0)
		cwnd *= ((struct bictcp *)inet_csk_ca(sk))->delay_min;
	else
		cwnd *= USEC_PER_MSEC;
	cwnd >>= BW_SCALE;
	return cwnd;
}

#if ! defined(CUBICPP_NODEBUG)
static u64 hystart_max_bw_bytes(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u64 bw;

	bw = hystart_max_bw(sk);
	bw *= (u64)tp->mss_cache * USEC_PER_SEC;
	bw >>= BW_SCALE;
	return bw;
}

static u64 hystart_max_bw_bps(const struct sock *sk)
{

	return hystart_max_bw_bytes(sk) * NBBY;
}

static u64 hystart_max_bw_mbps(const struct sock *sk)
{

	return hystart_max_bw_bps(sk) / 1024 / 1024;
}
#endif /* CUBICPP_NODEBUG */

static void hystart_bw_update(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u64 bw;

	if (! before(rs->prior_delivered, ca->bw_stamp)) {
		ca->bw_stamp = tp->delivered;
		ca->bw_cnt++;
        }
	if ((s64)rs->interval_us <= 0 || (s64)rs->delivered <= 0) {
		DP("invalid interval: %lu", rs->interval_us);
		return;
	}
	/* rs->interva_us is max(snd_interval_us, rcv_interval_us). */
	bw = div64_long((u64)rs->delivered << BW_SCALE, rs->interval_us);

	if (! rs->is_app_limited || bw >= hystart_max_bw(sk))
		minmax_running_max(&ca->bw, HYSTART_BW_WINDOW, ca->bw_cnt, bw);
#if 0
	DP("bandwith: %llu Mbps (%llu) sndint=%u,rcvint=%u,int=%lu,,delivered=%u",
	    (u64)tp->mss_cache * NBBY * USEC_PER_SEC * rs->delivered / rs->interval_us
	    / 1024 / 1024, bw, rs->snd_interval_us, rs->rcv_interval_us, rs->interval_us, rs->delivered);
	DP("bandwidth: %llu (%llu Mbps)", bw, ((NBBY * bw * tp->mss_cache * USEC_PER_SEC) >> BW_SCALE) / 1024 / 1024);
#endif /* 0 */
}

static inline void cubic_policer_detection(const struct sock *sk, const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	/*
	 * the first 10 segments are not paced.
	 * see tcp_output.c: tcp_update_skb_after_send().
	 */
	if (tp->data_segs_out > TCP_INIT_CWND * 10)
		return;
	if (rs->snd_interval_us * 2 < rs->rcv_interval_us)
		DP("policer exists: sndint=%u,rcvint=%u",
		    rs->snd_interval_us, rs->rcv_interval_us);
}

static inline void bictcp_hystart_reset(struct sock *sk)
{
#ifdef HYSTART_FULL_ROUND
	struct tcp_sock *tp = tcp_sk(sk);
#endif /* HYSTART_FULL_ROUND */
	struct bictcp *ca = inet_csk_ca(sk);

#if 0
	DP("hystart reset: unacked: %u, end_seq: %u\n", tp->snd_una, ca->end_seq);
#endif /* 0 */
	/* now use this for HyStart++ and CUBIC. */
	ca->epoch_start = tcp_jiffies32;
#ifdef HYSTART_FULL_ROUND
	ca->end_seq = tp->snd_nxt;
#endif /* HYSTART_FULL_ROUND */
	ca->prior_rtt = ca->curr_rtt;
	ca->prior_rtt_max = ca->curr_rtt_max;
	ca->curr_rtt = HYSTART_INFINITY;
	ca->curr_rtt_max = 0;
#if 0	/* XXX: here, should not clear these values... */
	ca->css_rtt = HYSTART_INFINITY;
	ca->css_rtt_max = 0;
#endif /* 0 */
	ca->sample_cnt = 0;
}

static inline bool hystart_delay_exceed(s64 curr, s64 base)
{

	return !! (curr >
	    base + HYSTART_DELAY_THRESH((u64)base >> HYSTART_RTT_DIVISOR_SHIFT));
}

static inline bool bictcp_hystart_delay_exceed(const struct sock *sk, const struct rate_sample *rs)
{
	struct bictcp *ca = inet_csk_ca(sk);
	u32 base;

	if (rs->is_retrans)
		return false;

#if 0
	/*
	 * This is not HyStart++ way, original but should be examined more.
	 */
	if (tcp_sk(sk)->data_segs_out > TCP_INIT_CWND &&
#define INITIAL_PACING_WORKAROUND
#ifdef INITIAL_PACING_WORKAROUND
	    (likely(ca->pacing_workaround) ||
	     tcp_sk(sk)->data_segs_out > TCP_INIT_CWND * 2) &&
#endif /* INITIAL_PACING_WORKAROUND */
	    rs->snd_interval_us +
	    (rs->snd_interval_us >> HYSTART_RTT_DIVISOR_SHIFT) <
	    rs->rcv_interval_us) {
		DP("sndrcvint: cwnd=%u,snd/rcv sndint=%u,rcvint=%u,"
		    "bw=%lluMbps,pacing=%luMbps",
		    tcp_snd_cwnd(tcp_sk(sk)),
		    rs->snd_interval_us, rs->rcv_interval_us,
		    hystart_max_bw_mbps(sk), PACING_RATE(sk));
		return true;
	}
#endif /* 0 */

#if 1	/* okay for wired.  NG for wireless??? */
	base = ca->delay_min;
	if (unlikely(base <= 0))
		return false;
#elif 0	/* okay for wired.  NG for wireless. */
	base = ca->prior_rtt;
	if (unlikely(base == HYSTART_INFINITY))
		base = ca->curr_rtt;
#elif 1	/* NG for wired??? */
	base = ca->prior_rtt_max;
	if (unlikely(base == 0))
		return false;
#endif /* 0 */
	return hystart_delay_exceed(rs->rtt_us, base);
}

static void bictcp_hystart_enter_css(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	WARN_ON(ca->round > HYSTART_CSS_ROUND_NONE);
	ca->round = 1;
	ca->css_rtt = ca->curr_rtt;
	ca->css_rtt_max = ca->curr_rtt_max;
	DP("enter CSS: segs=%u,cwnd=%u,ssthresh=%d,delay=min[%d]prior[%d,%d]curr[%d,%d]css[%d,%d],sample=%u/%u",
	    tcp_sk(sk)->data_segs_out,
	    tcp_snd_cwnd(tcp_sk(sk)), tcp_sk(sk)->snd_ssthresh,
	    ca->delay_min, ca->prior_rtt, ca->prior_rtt_max,
	    ca->curr_rtt, ca->curr_rtt_max, ca->css_rtt, ca->css_rtt_max,
	    ca->sample_cnt, HYSTART_MIN_SAMPLES);
}

static void bictcp_hystart_restart_css(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	DP("restart CSS[%u]: css_rtt=%u,curr_rtt=%u,sample=%u",
	    ca->round, ca->css_rtt, ca->curr_rtt, ca->sample_cnt);
	ca->css_rtt = HYSTART_INFINITY;
	ca->css_rtt_max = 0;
	ca->round = HYSTART_CSS_ROUND_NONE;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH; /* XXX: initial value? */
}

static void bictcp_hystart_try_restart_css(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	WARN_ON(ca->found);
#define HYSTART_JITTER_RATIO	0
#define	HYSTART_JITTER(rtt)	((rtt) * (100 + HYSTART_JITTER_RATIO) / 100)
	if (ca->css_rtt <= HYSTART_JITTER(ca->curr_rtt) ||
	    ca->curr_rtt_max <= HYSTART_JITTER(ca->css_rtt_max))
		return;
	bictcp_hystart_restart_css(sk);
}

static bool bictcp_hystart_exceed(struct sock *sk, const struct rate_sample *rs)
{
	struct bictcp *ca = inet_csk_ca(sk);

#if 0
	WARN_ON(ca->found);
#endif /* 0 */
	WARN_ON((s64)ca->prior_rtt < 0);

	if (rs->is_retrans)
		return false;

#if 0
	/* detect congestion by sending/receiving interval difference. */
	/* XXX: currently, does not work well... on wired... */
	if (tcp_sk(sk)->data_segs_out > TCP_INIT_CWND &&
#define INITIAL_PACING_WORKAROUND
#ifdef INITIAL_PACING_WORKAROUND
	    (likely(ca->pacing_workaround) ||
	     tcp_sk(sk)->data_segs_out > TCP_INIT_CWND * 2) &&
#endif /* INITIAL_PACING_WORKAROUND */
	    rs->snd_interval_us > 0 &&
	    rs->snd_interval_us + (rs->snd_interval_us >> 4)
	    < rs->rcv_interval_us) {
		DP("exceed: dsegs=%u,rtt=%lu,sndint=%u,rcvint=%u",
		    tcp_sk(sk)->data_segs_out,
		    rs->rtt_us, rs->snd_interval_us, rs->rcv_interval_us);
		return true;
	}
#endif /* 0 */

	if (ca->round == 0)
		return false;

#define HYSTART_CEIL(rtt)	((rtt) + (HYSTART_DELAY_THRESH(rtt) >> 1) + (HYSTART_DELAY_THRESH(rtt) >> 2))
#if 0
	if (ca->prior_rtt > HYSTART_CEIL(ca->css_rtt))
		return true;
#endif /* 0 */
#if 1
	if (ca->curr_rtt_max > HYSTART_CEIL(ca->css_rtt)) {
#else
	if (ca->curr_rtt_max > HYSTART_CEIL(ca->css_rtt_max)) {
#endif /* 0 */
		DP("hit the ceil: curr=%u,css*1.75=%u,curr_max=%u,css_max*1.75=%u,sndint=%u,rcvint=%u",
		    ca->curr_rtt, HYSTART_CEIL(ca->css_rtt),
		    ca->curr_rtt_max, HYSTART_CEIL(ca->css_rtt_max),
		    rs->snd_interval_us, rs->rcv_interval_us);
		return true;
	}
	return false;
}

static void bictcp_hystart_finish(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* XXX: should not use ca->found... */
	WARN_ON(ca->found);
	ca->found = 1;

	ca->round = HYSTART_CSS_ROUND_FINISH;
	ca->epoch_start = 0;	/* now pass this to CUBIC. */

	DP("CSS[%u]: finish: ssthresh: %d -> %d (cwnd), css_rtt=%u,css_rtt_max=%u",
	    ca->round, tp->snd_ssthresh, tcp_snd_cwnd(tp),
	    ca->css_rtt, ca->css_rtt_max);
	/* update CSS RTT even when never move to CSS. */
	if (ca->css_rtt > ca->curr_rtt)
		ca->css_rtt = ca->curr_rtt;
	if (ca->css_rtt_max < ca->curr_rtt_max)
		ca->css_rtt_max = ca->curr_rtt_max;
	if (tcp_snd_cwnd(tp) > ca->last_max_cwnd)
		ca->last_max_cwnd = tcp_snd_cwnd(tp);
	tp->snd_ssthresh = tcp_snd_cwnd(tp);
	NET_INC_STATS(sock_net(sk),
		      LINUX_MIB_TCPHYSTARTDELAYDETECT);
	NET_ADD_STATS(sock_net(sk),
		      LINUX_MIB_TCPHYSTARTDELAYCWND,
		      tcp_snd_cwnd(tp));
}

/* from tcp_input.c:tcp_update_pacing_rate(). */
static void cubictcp_update_pacing_rate(struct sock *sk, const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u64 rate;

#define HYSTART_RATE_SCALE		100
#ifdef WIRELESS_IS_OKAY
#define HYSTART_RATE_NORMAL		110
#define HYSTART_RATE_CONGESTED		100
#else /* Wired seems to be okay with below. */
#define HYSTART_RATE_NORMAL		101
#define HYSTART_RATE_CONGESTED		99
#endif /* ! WIRELESS_IS_OKAY */

	/* bandwidth in bps. */
	rate = (u64)tp->mss_cache * USEC_PER_SEC;
	/* XXX: maybe should consider lost packets or others... */
	rate *= max(tcp_snd_cwnd(tp), tp->packets_out);
	/* here should use recent RTT, not delay_min exceeding value. */
	if ((s64)rs->rtt_us > 0)
		do_div(rate, rs->rtt_us);
	else if ((s64)ca->delay_min > 0)
		do_div(rate, ca->delay_min); /* XXX */
	else
		do_div(rate, USEC_PER_MSEC); /* XXX: assume 1 msec. */

	if (ca->state == HYSTART_CONGESTED)
		rate *= HYSTART_RATE_CONGESTED;
	else
		rate *= HYSTART_RATE_NORMAL;
	rate /= HYSTART_RATE_SCALE;
	rate = min_t(u64, rate, READ_ONCE(sk->sk_max_pacing_rate));
	WRITE_ONCE(sk->sk_pacing_rate, rate);
#if 0
	u64 x = (u64)tp->mss_cache * tcp_snd_cwnd(tp) * USEC_PER_SEC;
	x = div64_u64(x, max(1, rs->rtt_us));
	DP("rate: %luMbps, cwnd=%u (%lluMbps) (rtt=%lu,min=%u)",
	    PACING_RATE(sk),
	    tcp_snd_cwnd(tp),
	    x * NBBY / 1024 / 1024, rs->rtt_us, ca->delay_min);
#endif /* 0 */
}

__bpf_kfunc static void cubictcp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
#define TEN_MSS_1MBPS	(100 * USEC_PER_MSEC)	/* 100ms for approx. 1Mbps */
#define LINUX_SRTT_SCALING	3
	struct rate_sample rs = { .rtt_us = tp->srtt_us >> LINUX_SRTT_SCALING };

	bictcp_reset(ca);

#define INITIAL_PACING_WORKAROUND
#ifdef INITIAL_PACING_WORKAROUND
	/*
	 * Linux kernel burstly emits 10 MSS packet ignoring pacing.
	 * this may cause losses in the initial slow start in some
	 * environment like author's :-(
	 * see tcp_output.c:tcp_update_skb_after_send().
	 */
	ca->pacing_workaround = 0;
	tp->data_segs_out += TCP_INIT_CWND + 1;
#endif /* INITIAL_PACING_WORKAROUND */

	if (hystart) {
		ca->bw_stamp = tp->delivered;
		ca->bw_cnt = 0;
		minmax_reset(&ca->bw, ca->bw_cnt, 0);
		ca->curr_rtt = HYSTART_INFINITY;
		ca->curr_rtt_max = 0;
		bictcp_hystart_reset(sk);
		ca->css_rtt = HYSTART_INFINITY;
		ca->css_rtt_max = 0;
	}

	if (!hystart && initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
	/* limit the initial 10 MSS pacing at 1Mbps. */
#define RTT_FOR_10MSS_AT_1MBPS		(100 * USEC_PER_MSEC)
	if (rs.rtt_us < RTT_FOR_10MSS_AT_1MBPS)
		rs.rtt_us = RTT_FOR_10MSS_AT_1MBPS;
	cubictcp_update_pacing_rate(sk, &rs);
	DP("[%u:%u]: initialized: srtt_us=%lu,pacing=%luMbps",
	    ntohs(inet_sk(sk)->inet_sport), ntohs(inet_sk(sk)->inet_dport),
	    rs.rtt_us, PACING_RATE(sk));
}

__bpf_kfunc static void cubictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_TX_START) {
		struct bictcp *ca = inet_csk_ca(sk);
		u32 now = tcp_jiffies32;
		s32 delta;

		delta = now - tcp_sk(sk)->lsndtime;

		/* We were application limited (idle) for a while.
		 * Shift epoch_start to keep cwnd growth to cubic curve.
		 */
		if (ca->epoch_start && delta > 0) {
			ca->epoch_start += delta;
			if (after(ca->epoch_start, now))
				ca->epoch_start = now;
		}
		return;
	}
}

#ifdef CUBICPP
/* initialize cwnd from memorized TCP metrics in kernel. */
/* XXX: copied from tcp_output.c. */
__u32 tcp_init_cwnd(const struct tcp_sock *tp, const struct dst_entry *dst)
{
	__u32 cwnd = (dst ? dst_metric(dst, RTAX_INITCWND) : 0);

	if (! cwnd)
		cwnd = TCP_INIT_CWND;
	return min_t(__u32, cwnd, tp->snd_cwnd_clamp);
}

/* RFC2861, slow part. Adjust cwnd, after it was not full during one rto.
 * As additional protections, we do not touch cwnd in retransmission phases,
 * and if application hit its sndbuf limit recently.
 */
static void tcp_cwnd_application_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Open &&
	    sk->sk_socket && !test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		/* Limited by application or receiver window. */
		u32 init_win = tcp_init_cwnd(tp, __sk_dst_get(sk));
		u32 win_used = max(tp->snd_cwnd_used, init_win);
		if (win_used < tcp_snd_cwnd(tp)) {
			tp->snd_ssthresh = tcp_current_ssthresh(sk);
			tcp_snd_cwnd_set(tp, (tcp_snd_cwnd(tp) + win_used) >> 1);
		}
		tp->snd_cwnd_used = 0;
	}
	tp->snd_cwnd_stamp = tcp_jiffies32;
}
#endif /* CUBICPP */

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

/*
 * Compute congestion window to use.
 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked)
{
	u32 delta, bic_target, max_cnt;
	u64 offs, t;

	ca->ack_cnt += acked;	/* count the number of ACKed packets */

	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
		return;

	/* The CUBIC function can update ca->cnt at most once per jiffy.
	 * On all cwnd reduction events, ca->epoch_start is set to 0,
	 * which will force a recalculation of ca->cnt.
	 */
	if (ca->epoch_start && tcp_jiffies32 == ca->last_time)
		goto tcp_friendliness;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_jiffies32;

	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_jiffies32;	/* record beginning */
		ca->ack_cnt = acked;			/* start counting */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (s32)(tcp_jiffies32 - ca->epoch_start);
	t += usecs_to_jiffies(ca->delay_min);
	/* change the unit from HZ to bictcp_HZ */
	t <<= BICTCP_HZ;
	do_div(t, HZ);

	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)                            /* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                          /* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		u32 scale = beta_scale;

		delta = (cwnd * scale) >> 3;
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}

		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	ca->cnt = max(ca->cnt, 2U);
}

#ifdef CUBICPP
__bpf_kfunc static u32 bictcp_hystart_slow_start(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 acked, cwnd, growth;

	growth = acked = rs->acked_sacked;
	WARN_ON(acked == 0);
	if (ca->round) {
		/* recent Linux kernel TCP enabling pacing but following RFC. */
#define HYSTART_L	8
		if (sk->sk_pacing_status == SK_PACING_NONE)
			growth = min(growth, HYSTART_L);
		growth += HYSTART_CSS_GROWTH_DIVISOR - 1;
		growth /= HYSTART_CSS_GROWTH_DIVISOR;
	}
	/* count the number of left ack considering divisor during CSS. */
	acked -= min(tcp_snd_cwnd(tp) + acked,
	    tp->snd_ssthresh) - tcp_snd_cwnd(tp);
	cwnd = min(tcp_snd_cwnd(tp) + growth, tp->snd_ssthresh);

#if 0
	DP("cwnd: %u -> %u, ssthresh=%u,acked=%u,growth=%u,sample=%u,sampleacked=%u,losses=%u,rtt=%lu,rtt_min=%u,round=%u,pacing=%luMbps\n", tcp_snd_cwnd(tp), cwnd, tp->snd_ssthresh, acked, growth, ca->sample_cnt, rs->acked_sacked, rs->losses, rs->rtt_us, ca->delay_min, ca->round, PACING_RATE(sk));
#endif
	tcp_snd_cwnd_set(tp, min(cwnd, tp->snd_cwnd_clamp));

	if (ca->round < HYSTART_CSS_ROUNDS)
		return 0;

	/* consume all acks if the last round still continues. */
	WARN_ON(ca->round != HYSTART_CSS_ROUNDS);
	if (ca->curr_rtt == HYSTART_INFINITY ||
	    ca->sample_cnt != 0)
		return 0;

	bictcp_hystart_reset(sk);
	bictcp_hystart_finish(sk);
	return acked;
}

__bpf_kfunc static void cubictcp_cong_avoid(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 acked = rs->acked_sacked;

	if (! tcp_is_cwnd_limited(sk)) {
#if 0
		DP("cwnd is not fully consumed");
#endif /* 0 */
		return;
	}

	/* original CUBIC does not consider if slow start finished or not. */
	if (hystart_is_active(sk)) {
		WARN_ON(ca->found);
		acked = bictcp_hystart_slow_start(sk, rs);
		if (! acked)
			return;
	}
	bictcp_update(ca, tcp_snd_cwnd(tp), acked);
#ifdef CUBICPP
	/* XXX: should make sure if this is right place or not... */
	if (! tcp_is_cwnd_limited(sk) &&
	    READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_slow_start_after_idle) &&
	    (s32)(tcp_jiffies32 - tcp_sk(sk)->snd_cwnd_stamp) >= inet_csk(sk)->icsk_rto)
		tcp_cwnd_application_limited(sk);
#ifdef CUBICPP_DEBUG
	DP("%s%s: %s: cwnd: %u -> %u, segs=%u,lcwnd=%u,lmaxcwnd=%u,cnt=%u,acked=%u\n",
	    tcp_is_sack(tcp_sk(sk)) ? "SACK" : "Reno",
	    tcp_is_rack(sk) ? "(RACK)" : "",
	    tcp_state_name(inet_csk(sk)->icsk_ca_state),
	    tcp_snd_cwnd(tcp_sk(sk)), cwnd,
	    tcp_sk(sk)->data_segs_out, ca->last_cwnd, ca->last_max_cwnd, ca->cnt, acked);
#endif /* CUBICPP_DEBUG */
#endif /* CUBICPP */
	tcp_cong_avoid_ai(tp, ca->cnt, acked);
}

/*
 * called when a packet loss is detected with SACK, RACK, DupAck or RTO.
 * returned value will be new ssthresh.
 */
__bpf_kfunc static u32 cubictcp_recalc_ssthresh(struct sock *sk)
{

	return tcp_sk(sk)->snd_ssthresh;
}
#endif /* CUBICPP */

__bpf_kfunc static void cubictcp_state(struct sock *sk, u8 new_state)
{
#ifdef CUBICPP
	struct bictcp *ca = inet_csk_ca(sk);

#if 1
	DP("%s%s: %s(%u)->%s(%u): dsegs=%u,segs=%u,ssthresh=%u,prior=%u,cwnd=%u,prior=%u,max cwnd=%u,cnt=%u,ca_cwnd=%u,retrans=%u,sacked out=%u,lost out=%u,retrans out=%u,inflight=%u,pacing=%luMbps\n",
	    tcp_is_sack(tcp_sk(sk)) ? "SACK" : "Reno",
	    tcp_is_rack(sk) ? "(RACK)" : "",
	    tcp_state_name(inet_csk(sk)->icsk_ca_state),
	    inet_csk(sk)->icsk_ca_state,
	    tcp_state_name(new_state), new_state,
	    tcp_sk(sk)->data_segs_out, tcp_sk(sk)->segs_out,
	    tcp_sk(sk)->snd_ssthresh, tcp_sk(sk)->prior_ssthresh,
	    tcp_snd_cwnd(tcp_sk(sk)), tcp_sk(sk)->prior_cwnd,
	    ca->last_max_cwnd,
	    ca->cnt, ca->tcp_cwnd,
	    tcp_sk(sk)->total_retrans,
	    tcp_sk(sk)->sacked_out, tcp_sk(sk)->lost_out,
	    tcp_sk(sk)->retrans_out, tcp_packets_in_flight(tcp_sk(sk)),
	    PACING_RATE(sk));
#endif
	switch (new_state) {
	case TCP_CA_Open:
		break;
	case TCP_CA_Recovery:
		/* original CUBIC continues slow start... */
		break;
	case TCP_CA_Loss:
		bictcp_reset(inet_csk_ca(sk));
		bictcp_hystart_reset(sk);
		ca->css_rtt = HYSTART_INFINITY;
		ca->css_rtt_max = 0;
		ca->round = 0;
		break;
	}
#endif /* CUBICPP */
}

#define HYSTART_LOSS_THRESHOLD	2
#define HYSTART_LOSS_SCALE	100

static bool cubictcp_loss_exceed(struct sock *sk, const struct rate_sample *rs)
{
	struct bictcp *ca = inet_csk_ca(sk);

#if 0
	struct tcp_sock *tp = tcp_sk(sk);
	return !! (max(tp->lost_out, tp->retrans_out) * HYSTART_LOSS_SCALE / tp->packets_out > HYSTART_LOSS_THRESHOLD);
#else
	/* XXX: remove this... */
	if (rs->losses > 0)
		return true;
	if (rs->losses * HYSTART_LOSS_SCALE / (rs->losses + rs->delivered) <
	    HYSTART_LOSS_THRESHOLD)
		return false;
	if (tcp_snd_cwnd(tcp_sk(sk)) <= hystart_max_bw_cwnd(sk, rs)) {
		DP("trivial loss: losses=%u,acked=%u,delivered=%u,cwnd=%u,dcwnd=%u,rtt=%lu,rttmin=%u",
		    rs->losses, rs->acked_sacked, rs->delivered, tcp_snd_cwnd(tcp_sk(sk)),
		    hystart_max_bw_cwnd(sk, rs),
		    rs->rtt_us, ca->delay_min);
		return false;
	}

	return true;
#endif
}

static bool cubictcp_delay_exceed(struct sock *sk, const struct rate_sample *rs)
{
	struct bictcp *ca = inet_csk_ca(sk);

	if (rs->is_retrans)
		return false;
	/* XXX: follow CSS processing during CSS... */
	if (hystart_is_active(sk))
		return false;
	WARN_ON(! ca->found);
	if (! ca->found)
		return false;
	if (rs->rtt_us < 0 || ca->delay_min <= 0)
		return false;
#if 0	/* NG for wireless??? */
	return !! (rs->rtt_us > HYSTART_CEIL(ca->delay_min));
#elif 0
	return !! (rs->rtt_us > HYSTART_CEIL(ca->css_rtt_max));
#else
	if (ca->curr_rtt == HYSTART_INFINITY ||
	    ca->curr_rtt <= HYSTART_CEIL(ca->css_rtt_max))
		return false;
	if (ca->prior_rtt == HYSTART_INFINITY ||
	    ca->prior_rtt <= HYSTART_CEIL(ca->css_rtt_max))
		return false;
	if (PACING_RATE(sk) <= hystart_max_bw_mbps(sk))
		return false;
	return true;
#endif /* 0 */
}

/* XXX: copied from tcp_input.c. */
static void cubictcp_cwnd_reduction(struct sock *sk, const struct rate_sample *rs, bool is_snd_una_changed)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int sndcnt = 0;
	int delta = tp->snd_ssthresh - tcp_packets_in_flight(tp);
	u32 cwnd;

	if (rs->acked_sacked <= 0 || WARN_ON_ONCE(! tp->prior_cwnd))
		return;

	WARN_ON(inet_csk(sk)->icsk_ca_state > TCP_CA_Recovery);
	if (inet_csk(sk)->icsk_ca_state < TCP_CA_Recovery) {
		cwnd = max(tcp_snd_cwnd(tp) * gamma / BICTCP_BETA_SCALE, 1U);
		tcp_snd_cwnd_set(tp, cwnd);
		return;
	}

	tp->prr_delivered += rs->acked_sacked;
	if (delta < 0) {
		u64 dividend = (u64)tp->snd_ssthresh * tp->prr_delivered +
			       tp->prior_cwnd - 1;
		sndcnt = div_u64(dividend, tp->prior_cwnd) - tp->prr_out;
	} else {
		sndcnt = max_t(int, tp->prr_delivered - tp->prr_out,
		    rs->acked_sacked);
		if (is_snd_una_changed && ! rs->losses)
			sndcnt++;
		sndcnt = min(delta, sndcnt);
	}
	sndcnt = max(sndcnt, (tp->prr_out ? 0 : 1));
	/* Force a fast retransmit upon entering fast recovery */
	cwnd = max(tcp_packets_in_flight(tp) + sndcnt, tcp_snd_cwnd(tp) / 2);
	tcp_snd_cwnd_set(tp, cwnd);
}

static bool cubictcp_in_cwnd_reduction(struct sock *sk, const struct rate_sample *rs)
{

	if (cubictcp_delay_exceed(sk, rs))
		return true;
	if (! tcp_in_cwnd_reduction(sk))
		return false;
	if (! cubictcp_loss_exceed(sk, rs))
		return false;
	return true;
}

/* from tcp_input.c. */
/* The cwnd reduction in CWR and Recovery uses the PRR algorithm in RFC 6937.
 * It computes the number of packets to send (sndcnt) based on packets newly
 * delivered:
 *   1) If the packets in flight is larger than ssthresh, PRR spreads the
 *	cwnd reductions across a full RTT.
 *   2) Otherwise PRR uses packet conservation to send as much as delivered.
 *      But when SND_UNA is acked without further losses,
 *      slow starts cwnd up to ssthresh to speed up the recovery.
 */
static void cubictcp_init_cwnd_reduction(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->high_seq = tp->snd_nxt;
	tp->tlp_high_seq = 0;
	tp->snd_cwnd_cnt = 0;
	tp->prior_cwnd = tcp_snd_cwnd(tp);
	tp->prr_delivered = 0;
	tp->prr_out = 0;
	tp->snd_ssthresh = inet_csk(sk)->icsk_ca_ops->ssthresh(sk);
	/* open code of tcp_ecn_queue_cwr(tp). */
	if (tp->ecn_flags & TCP_ECN_OK)
		tp->ecn_flags |= TCP_ECN_QUEUE_CWR;
}

static void cubictcp_ssthresh(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 gain = beta;

	ca->epoch_start = 0;	/* end of epoch */

	if (inet_csk(sk)->icsk_ca_state <= TCP_CA_Recovery) {
		if (inet_csk(sk)->icsk_ca_state < TCP_CA_Recovery)
			gain = gamma;
		ca->last_max_cwnd = tcp_snd_cwnd(tp);
	} else {
		/* Wmax and fast convergence */
		if (tcp_snd_cwnd(tp) < ca->last_max_cwnd && fast_convergence)
			ca->last_max_cwnd = (tcp_snd_cwnd(tp) * (BICTCP_BETA_SCALE + beta))
				/ (2 * BICTCP_BETA_SCALE);
		else
			ca->last_max_cwnd = tcp_snd_cwnd(tp);
	}
	tp->snd_ssthresh = max((tcp_snd_cwnd(tp) * gain) / BICTCP_BETA_SCALE, 2U);
#if 1
#ifdef CUBICPP
	DP("%s: cwnd=%u,ssthresh=%u,cnt=%u,CAcwnd=%u,last_max_cwnd=%u,acked=%u,lost=%u,retrans=%u,rtt=%u,min=%u\n",
	   tcp_state_name(inet_csk(sk)->icsk_ca_state),
	   tcp_snd_cwnd(tp), tp->snd_ssthresh, ca->cnt, ca->tcp_cwnd, ca->last_max_cwnd,
	   rs->acked_sacked, rs->losses, tp->retrans_out, ca->curr_rtt, ca->delay_min);
#endif /* CUBICPP */
#endif /* 0 */
}

__bpf_kfunc static void cubictcp_acked(struct sock *sk, const struct rate_sample *sample);

__bpf_kfunc static void cubictcp_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	bool is_snd_una_changed = false;

	/* similar to tcp_input.c:tcp_cong_control(). */

#if 0
	/* i do not know this is necessary or not, but leave it as is. */
	if (likely(after(tp->snd_una, ca->prior_snd_una))) {
		ca->prior_snd_una = tp->snd_una;
		is_snd_una_changed = true;
	}
#endif /* 0 */

	/* ignore unreliable sample of SACK reneging. */
	if (rs->delivered == -1)
		return;

	cubictcp_acked(sk, rs);

	if (cubictcp_in_cwnd_reduction(sk, rs)) {
		if (ca->state != HYSTART_CONGESTED) {
			ca->state = HYSTART_CONGESTED;
			if (hystart_is_active(sk))
				bictcp_hystart_finish(sk);
			else
				/* do not reduce on HyStart. */
				cubictcp_ssthresh(sk, rs);
			cubictcp_init_cwnd_reduction(sk);
			DP("recovering: %s%s%s: cwnd=%u,ssthresh=%u,dlvcwnd=%u,delivered=%u,acked=%u,losses=%u,lost_out=%u,retrans_out=%u,packets=%u,sample=%u,round=%u,pacing=%luMbps,dlvrate=%lluMbps,sndint=%u,rcvint=%u\n",
			    hystart_is_active(sk) ? "(HyStart)" : "",
			    cubictcp_loss_exceed(sk, rs) ? " loss" : "",
			    cubictcp_delay_exceed(sk, rs) ? " delay" : "",
			    tcp_snd_cwnd(tp), tp->snd_ssthresh,
			    hystart_max_bw_cwnd(sk, rs), rs->delivered,
			    rs->acked_sacked, rs->losses, tp->lost_out,
			    tp->retrans_out, tp->packets_out, ca->sample_cnt,
			    ca->round, PACING_RATE(sk), hystart_max_bw_mbps(sk),
			    rs->snd_interval_us, rs->rcv_interval_us);
		}
		cubictcp_cwnd_reduction(sk, rs, is_snd_una_changed);
	} else if (bictcp_hystart_exceed(sk, rs)) {
		tcp_snd_cwnd_set(tp, max(tcp_snd_cwnd(tp) * 98 / 100, 2));
		tp->snd_cwnd_stamp = tcp_jiffies32;
	} else {
		if (inet_csk(sk)->icsk_ca_state < TCP_CA_Recovery)
			ca->state = HYSTART_OPEN;
		cubictcp_cong_avoid(sk, rs);
		tp->snd_cwnd_stamp = tcp_jiffies32;
	}
	cubictcp_update_pacing_rate(sk, rs);
}

__bpf_kfunc static u32 cubictcp_undo_cwnd(struct sock *sk)
{
#if ! defined(CUBICPP_NODEBUG)
	struct bictcp *ca = inet_csk_ca(sk);
#endif /* ! CUBICPP_NODEBUG */

	DP("cnt: %u, cwnd: %u, prior cwnd: %u, last_max_cwnd: %u\n",
	   ca->cnt, ca->tcp_cwnd, tcp_sk(sk)->prior_cwnd, ca->last_max_cwnd);
	return tcp_reno_undo_cwnd(sk);
}

/* Account for TSO/GRO delays.
 * Otherwise short RTT flows could get too small ssthresh, since during
 * slow start we begin with small TSO packets and ca->delay_min would
 * not account for long aggregation delay when TSO packets get bigger.
 * Ideally even with a very small RTT we would like to have at least one
 * TSO packet being sent and received by GRO, and another one in qdisc layer.
 * We apply another 100% factor because @rate is doubled at this point.
 * We cap the cushion to 1ms.
 */
static u32 hystart_ack_delay(const struct sock *sk)
{
	unsigned long rate;

	rate = READ_ONCE(sk->sk_pacing_rate);
	if (!rate)
		return 0;
	return min_t(u64, USEC_PER_MSEC,
		     div64_ul((u64)sk->sk_gso_max_size * 4 * USEC_PER_SEC, rate));
}

static void hystart_update_ack_train(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 threshold, duration;

	if (rs->rcv_interval_us == -1)
		return;
	if (rs->rcv_interval_us > hystart_ack_delta_us)
		return;
	/*
	 * HyStart ack train triggers if consecuentive
	 * acks within delay_min / 2.
	 */
	threshold = ca->delay_min + hystart_ack_delay(sk);
	/*
	 * CUBIC++ always employs packet pacing.
	 * pacing might have delayed packets up ot RTT/2.
	 * leave the original code as is.
	 */
#ifdef CUBIC_DOES_NOT_PACE_BY_ITSELF
	if (sk->sk_pacing_status == SK_PACING_NONE)
		threshold >>= 1;
#endif /* CUBIC_DOES_NOT_PACE_BY_ITSELF */

	/*
	 * XXX: this is not original code.
	 *	but private space of struct bictcp
	 *	is not limitied.
	 *	So, here borrow other variables.
	 */
#if HZ < USEC_PER_MSEC
#error not enough clock resolution.
#endif /* HZ < USEC_PER_SEC */
	duration = tcp_jiffies32 - ca->epoch_start;
	if (ca->epoch_start &&
	    duration > (HZ / USEC_PER_MSEC) * threshold / MSEC_PER_SEC) {
		DP("hystart_ack_train (%u, %u > %u) delay_min %u (+ ack_delay %u) cwnd %u\n",
		    rs->rcv_interval_us, duration, threshold,
		    ca->delay_min, hystart_ack_delay(sk), tcp_snd_cwnd(tp));
		pr_debug("hystart_ack_train (%u > %u) delay_min %u (+ ack_delay %u) cwnd %u\n",
			 duration, threshold,
			 ca->delay_min, hystart_ack_delay(sk), tcp_snd_cwnd(tp));

		/* XXX: do not enter here though...  */
		if (! hystart_is_active(sk))
			return;

		bictcp_hystart_finish(sk);
		NET_INC_STATS(sock_net(sk),
			      LINUX_MIB_TCPHYSTARTTRAINDETECT);
		NET_ADD_STATS(sock_net(sk),
			      LINUX_MIB_TCPHYSTARTTRAINCWND,
			      tcp_snd_cwnd(tp));
	}
}

static void hystart_update(struct sock *sk, const struct rate_sample *rs)
{
	struct bictcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

#ifdef INITIAL_PACING_WORKAROUND
	if (unlikely(! ca->pacing_workaround) &&
	    tp->data_segs_out > TCP_INIT_CWND << 1) {
		ca->pacing_workaround = 1;
		tp->data_segs_out -= TCP_INIT_CWND;
	}
#endif /* INITIAL_PACING_WORKAROUND */

	/*
	 * ignore retnramitted packet because its inteval/delay is inaccurate
	 * beacuse it may contain RTO.
	 */
	if (rs->is_retrans)
		return;

	hystart_bw_update(sk, rs);
	cubic_policer_detection(sk, rs);

	ca->sample_cnt++;
	if (hystart_is_active(sk)) {
		if (bictcp_hystart_exceed(sk, rs)) {
			/* this prevents cwnd increase on this ack reception. */
			bictcp_hystart_finish(sk);
			cubictcp_init_cwnd_reduction(sk);
			cubictcp_cwnd_reduction(sk, rs, false /* XXX */);
			return;
		}
	}
	if (ca->round == 1) {
		if (ca->css_rtt > ca->curr_rtt)
			ca->css_rtt = ca->curr_rtt;
		if (ca->css_rtt_max < ca->curr_rtt_max)
			ca->css_rtt_max = ca->curr_rtt_max;
	}
	if (hystart_detect & HYSTART_ACK_TRAIN)
		hystart_update_ack_train(sk, rs);
	if (ca->sample_cnt < HYSTART_MIN_SAMPLES)
		return;
	if (ca->round == HYSTART_CSS_ROUND_NONE) {
		if (bictcp_hystart_delay_exceed(sk, rs))
			bictcp_hystart_enter_css(sk);
	} else if (ca->round <= HYSTART_CSS_ROUNDS)
		bictcp_hystart_try_restart_css(sk);
#ifdef HYSTART_FULL_ROUND
	if (! after(tp->snd_una, ca->end_seq))
		return;
#endif /* HYSTART_FULL_ROUND */
	/* XXX: just for debug logging... */
	if (ca->round > HYSTART_CSS_ROUND_NONE &&
	    ca->round <= HYSTART_CSS_ROUNDS)
		DP("CSS[%u]: cwnd=%u,ssthresh=%d,delay=min[%d]prior[%d,%d]curr[%d,%d]css[%d,%d],thresh=%d,sample=%d/%d",
		    ca->round, tcp_snd_cwnd(tp), tp->snd_ssthresh,
		    ca->delay_min,
		    ca->prior_rtt, ca->prior_rtt_max,
		    ca->curr_rtt, ca->curr_rtt_max,
		    ca->css_rtt, ca->css_rtt_max,
		    HYSTART_DELAY_THRESH(ca->prior_rtt >> 3),
		    ca->sample_cnt, HYSTART_MIN_SAMPLES);
	/* the last round finshes after cwnd is increased in slow start. */
	if (ca->round == HYSTART_CSS_ROUNDS) {
		/* XXX: dirty hack. */
		ca->sample_cnt = 0;
		return;
	}
	bictcp_hystart_reset(sk);
	if (ca->found)
		return;
	if (ca->round == HYSTART_CSS_ROUND_NONE)
		return;
	if (ca->round < HYSTART_CSS_ROUNDS)
		ca->round++;
}

__bpf_kfunc static void cubictcp_acked(struct sock *sk, const struct rate_sample *sample)
{
	struct bictcp *ca = inet_csk_ca(sk);
	long delay;

	/* Some calls are for duplicates without timetamps */
	if (sample->rtt_us < 0)
		return;

#ifdef CUBICPP
	if (sample->acked_sacked == 0) {
		DP("no ack");
		return;
	}
	if (sample->is_ack_delayed) {
		DP("delayed ack");
		return;
	}
	if (sample->is_retrans)
		return;
#else /* CUBICPP */
	/* Discard delay samples right after fast recovery */
	if (ca->epoch_start && (s32)(tcp_jiffies32 - ca->epoch_start) < HZ)
		return;
#endif /* ! CUBICPP */

	delay = sample->rtt_us;
	if (delay == 0)
		delay = 1;

#ifdef CUBICPP
	if (ca->curr_rtt > delay)
		ca->curr_rtt = delay;
	if (ca->curr_rtt_max < delay)
		ca->curr_rtt_max = delay;
	if (hystart)
		hystart_update(sk, sample);

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;
#endif /* CUBICPP */
}

static struct tcp_congestion_ops cubictcp __read_mostly = {
#ifdef CUBICPP /* allow this congestion control by default. */
	.flags		= TCP_CONG_NON_RESTRICTED,
#endif /* CUBICPP */
	.init		= cubictcp_init,
	.ssthresh	= cubictcp_recalc_ssthresh,
#ifdef CUBICPP
	.cong_control	= cubictcp_cong_control,
#else /* CUBICPP */
	.cong_avoid	= cubictcp_cong_avoid,
#endif /* ! CUBICPP */
	.set_state	= cubictcp_state,
#ifdef CUBICPP
	.undo_cwnd	= cubictcp_undo_cwnd,
#else /* CUBICPP */
	.undo_cwnd	= tcp_reno_undo_cwnd,
#endif /* CUBICPP */
	.cwnd_event	= cubictcp_cwnd_event,
#if ! defined(CUBICPP)
	.pkts_acked     = cubictcp_acked,
#endif /* ! CUBICPP */
	.owner		= THIS_MODULE,
#ifdef CUBICPP
	.name		= "cubic++",
#endif /* CUBICPP */
};

BTF_SET8_START(tcp_cubic_check_kfunc_ids)
#ifdef CONFIG_X86
#ifdef CONFIG_DYNAMIC_FTRACE
BTF_ID_FLAGS(func, cubictcp_init)
BTF_ID_FLAGS(func, cubictcp_recalc_ssthresh)
BTF_ID_FLAGS(func, cubictcp_cong_avoid)
BTF_ID_FLAGS(func, cubictcp_state)
BTF_ID_FLAGS(func, cubictcp_cwnd_event)
BTF_ID_FLAGS(func, cubictcp_acked)
#endif
#endif
BTF_SET8_END(tcp_cubic_check_kfunc_ids)

static const struct btf_kfunc_id_set tcp_cubic_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &tcp_cubic_check_kfunc_ids,
};

static int __init cubictcp_register(void)
{
	int ret;

	DP("minmax: %zu, %zu vs %zu", sizeof(struct minmax), sizeof(struct bictcp), ICSK_CA_PRIV_SIZE);
	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);

	/* Precompute a bunch of the scaling factors that are used per-packet
	 * based on SRTT of 100ms
	 */

	beta_scale = 8*(BICTCP_BETA_SCALE+beta) / 3
		/ (BICTCP_BETA_SCALE - beta);

	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */
	do_div(cube_factor, bic_scale * 10);

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &tcp_cubic_kfunc_set);
	if (ret < 0)
		return ret;
	return tcp_register_congestion_control(&cubictcp);
}

static void __exit cubictcp_unregister(void)
{
	tcp_unregister_congestion_control(&cubictcp);
}

module_init(cubictcp_register);
module_exit(cubictcp_unregister);

MODULE_AUTHOR("Sangtae Ha, Stephen Hemminger");
MODULE_LICENSE("GPL");
#ifdef CUBICPP
MODULE_AUTHOR("Motoyuki OHMORI");
MODULE_DESCRIPTION("CUBIC TCP for Starlink");
#else /* CUBICPP */
MODULE_DESCRIPTION("CUBIC TCP");
#endif /* ! CUBICPP */
MODULE_VERSION("2.3");
