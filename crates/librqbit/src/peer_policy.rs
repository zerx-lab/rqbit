//! Pluggable per-peer admission and upload policy.
//!
//! An embedding application installs a [`PeerPolicy`] through
//! [`SessionOptions::peer_policy`](crate::SessionOptions::peer_policy). The session then asks it
//! whether an address may be connected to at all ([`PeerPolicy::admit`]) and reports what every
//! live connection does ([`PeerPolicy::on_event`]). The answer to an event is a [`PeerVerdict`]
//! that is applied to that one connection and can only escalate (it is sticky).
//!
//! Everything that is not the public contract (the per-connection upload gate, the throttled
//! upload bucket, the glue used by the peer handler) lives here too, so that the call sites in
//! the session and the peer handler stay one-liners.

use std::{
    collections::HashMap,
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
    },
};

use bitvec::{order::Msb0, slice::BitSlice};
use librqbit_core::{
    hash_id::Id20,
    lengths::{ChunkInfo, Lengths},
};
use parking_lot::Mutex;
use peer_binary_protocol::Message;
use tokio::sync::mpsc::UnboundedSender;
use tracing::trace;

use crate::{
    limits::{Limits, LimitsConfig},
    peer_connection::WriterRequest,
};

/// Static facts about the connection an event belongs to.
#[derive(Debug, Clone, Copy)]
pub struct PeerCtx<'a> {
    pub info_hash: Id20,
    /// The remote address. IPv4-mapped IPv6 addresses are normalized to plain IPv4.
    pub addr: SocketAddr,
    /// `info.private` of the torrent.
    pub private: bool,
    pub total_length: u64,
    pub piece_length: u32,
    pub num_pieces: u32,
    /// We already have every selected piece of the torrent.
    pub we_are_seeding: bool,
    pub _p: PhantomData<&'a ()>,
}

/// Something a peer did, or something that happened to the connection.
#[derive(Debug, Clone, Copy)]
pub enum PeerEvent<'a> {
    /// The BitTorrent handshake completed.
    Handshake {
        peer_id: Id20,
        reserved: u64,
        incoming: bool,
    },
    /// The peer's extended handshake arrived; `client` is its `v` field.
    ExtendedHandshake {
        client: Option<&'a str>,
    },
    /// A whole bitfield arrived (already cut to `num_pieces` bits).
    Bitfield {
        bits: &'a BitSlice<u8, Msb0>,
    },
    Have {
        piece: u32,
    },
    /// A valid request for a block we have. It is also reported while the connection is choked
    /// by the policy (the request is then ignored); `peer_claims_piece` tells whether the peer
    /// had announced the piece through its bitfield or a HAVE before asking for it.
    Request {
        piece: u32,
        begin: u32,
        length: u32,
        peer_claims_piece: bool,
    },
    Cancel {
        piece: u32,
        begin: u32,
        length: u32,
    },
    /// A block was written to the socket successfully.
    Uploaded {
        piece: u32,
        begin: u32,
        length: u32,
    },
    /// The connection ended. `bits` is the last known bitfield of the peer, `None` when the peer
    /// never announced anything or its state was already dropped by the torrent (it is dropped
    /// when both sides turned out to have the whole torrent). The verdict is ignored.
    Disconnected {
        bits: Option<&'a BitSlice<u8, Msb0>>,
    },
}

/// What to do with one connection. Variants are ordered by severity and a connection never
/// goes back to a milder state once a stronger verdict was returned for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PeerVerdict {
    Allow = 0,
    /// Serve the connection's uploads from the session-wide throttled queue
    /// ([`Session::set_throttled_upload_bps`](crate::Session::set_throttled_upload_bps)).
    Throttle = 1,
    /// Send a choke, drop the queued upload requests and ignore the following ones. The
    /// connection stays up.
    Choke = 2,
    /// Close the connection.
    Disconnect = 3,
}

impl PeerVerdict {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Allow,
            1 => Self::Throttle,
            2 => Self::Choke,
            _ => Self::Disconnect,
        }
    }
}

/// Implementations are called from the connection tasks: they must neither block nor do IO, and
/// must not call back into the [`Session`](crate::Session).
pub trait PeerPolicy: Send + Sync + 'static {
    /// Called before a connection is accepted (before MSE / handshake) or dialed. `false`
    /// refuses it and is counted as a blocked connection. The address is normalized the same way
    /// as [`PeerCtx::addr`].
    fn admit(&self, ip: IpAddr) -> bool;

    /// Asked again about an address `admit` refused earlier, to find out whether it may be dialed
    /// now ([`Session::readmit_refused_peers`](crate::Session::readmit_refused_peers)). It is not
    /// a connection attempt, so implementations can leave it out of their "refused connections"
    /// statistics. Defaults to `admit`.
    fn readmit(&self, ip: IpAddr) -> bool {
        self.admit(ip)
    }

    /// Called for every event of every live connection, a block (16 KiB) at a time on the upload
    /// path.
    fn on_event(&self, ctx: &PeerCtx<'_>, event: PeerEvent<'_>) -> PeerVerdict;
}

/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) become plain IPv4.
pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

pub(crate) fn canonical_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical_ip(addr.ip()), addr.port())
}

/// (piece, begin, length): how requests and cancels identify a block.
type BlockKey = (u32, u32, u32);

fn block_key(chunk: &ChunkInfo) -> BlockKey {
    (chunk.piece_index.get(), chunk.offset, chunk.size)
}

#[derive(Default)]
struct PendingBlock {
    queued: u32,
    cancelled: u32,
}

#[derive(Default)]
struct GateBlocks {
    blocks: HashMap<BlockKey, PendingBlock>,
    // Sums over `blocks`.
    queued: u32,
    cancelled: u32,
}

/// How many accepted upload requests may wait for one connection. Requests above it are
/// ignored; the peer asks again for what it didn't get. The limit is announced as `reqq`.
pub(crate) const MAX_QUEUED_UPLOADS_PER_PEER: u32 = 500;
/// The same for a throttled connection: the throttled queue is shared and slow, a few blocks per
/// connection keep its memory bounded and let throttled peers take turns.
pub(crate) const MAX_QUEUED_THROTTLED_UPLOADS_PER_PEER: u32 = 4;

/// Shared between the reader side of a connection (which registers requests and cancels), the
/// upload schedulers and the writer: it knows which accepted upload requests must still be
/// served. A request is dropped when the peer cancelled it, or when the connection was choked or
/// disconnected by the policy.
#[derive(Default)]
pub(crate) struct UploadGate {
    level: AtomicU8,
    // Copies of the sums in `pending`, so that the common case (nothing cancelled, nothing
    // choked) is decided without taking the lock.
    queued: AtomicU32,
    cancelled: AtomicU32,
    pending: Mutex<GateBlocks>,
}

impl UploadGate {
    pub fn level(&self) -> PeerVerdict {
        PeerVerdict::from_u8(self.level.load(Ordering::Acquire))
    }

    /// Escalates the connection's verdict. Returns the previous one.
    fn raise(&self, to: PeerVerdict) -> PeerVerdict {
        PeerVerdict::from_u8(self.level.fetch_max(to as u8, Ordering::AcqRel))
    }

    /// A request for the block was accepted for upload, unless `max_queued` requests of the
    /// connection already wait.
    pub fn register(&self, key: BlockKey, max_queued: u32) -> bool {
        let mut g = self.pending.lock();
        if g.queued >= max_queued {
            return false;
        }
        g.blocks.entry(key).or_default().queued += 1;
        g.queued += 1;
        self.queued.store(g.queued, Ordering::Release);
        true
    }

    /// The peer cancelled the block. Only cancels a request that is still waiting: one that
    /// was already sent (or never made) has nothing to cancel, and remembering the cancel would
    /// swallow a later legitimate request for the same block.
    pub fn cancel(&self, key: BlockKey) {
        if self.queued.load(Ordering::Acquire) == 0 {
            return;
        }
        let mut g = self.pending.lock();
        if let Some(b) = g.blocks.get_mut(&key)
            && b.cancelled < b.queued
        {
            b.cancelled += 1;
            g.cancelled += 1;
            self.cancelled.store(g.cancelled, Ordering::Release);
        }
    }

    fn drop_queued(&self) {
        let mut g = self.pending.lock();
        *g = GateBlocks::default();
        self.queued.store(0, Ordering::Release);
        self.cancelled.store(0, Ordering::Release);
    }

    fn is_dropped(&self, key: &BlockKey) -> bool {
        self.level() >= PeerVerdict::Choke
            || (self.cancelled.load(Ordering::Acquire) > 0
                && self
                    .pending
                    .lock()
                    .blocks
                    .get(key)
                    .is_some_and(|b| b.cancelled > 0))
    }

    /// Takes one waiting request for the block out of the queue. Returns whether it has to be
    /// served.
    pub fn release(&self, key: BlockKey) -> bool {
        if self.queued.load(Ordering::Acquire) == 0 {
            // Nothing waits (the queue was dropped by a choke, or the request never was one).
            return self.level() < PeerVerdict::Choke;
        }
        let mut g = self.pending.lock();
        let mut cancelled = false;
        if let Some(b) = g.blocks.get_mut(&key) {
            b.queued -= 1;
            if b.cancelled > 0 {
                b.cancelled -= 1;
                cancelled = true;
            }
            if b.queued == 0 {
                g.blocks.remove(&key);
            }
            g.queued -= 1;
            if cancelled {
                g.cancelled -= 1;
            }
            self.queued.store(g.queued, Ordering::Release);
            self.cancelled.store(g.cancelled, Ordering::Release);
        }
        drop(g);
        !cancelled && self.level() < PeerVerdict::Choke
    }

    /// For schedulers: `false` means the request was dropped (and is released).
    pub fn keep(&self, chunk: &ChunkInfo) -> bool {
        let key = block_key(chunk);
        if self.is_dropped(&key) {
            self.release(key);
            return false;
        }
        true
    }

    /// For the writer, right before it reads the block from disk.
    pub fn should_upload(&self, chunk: &ChunkInfo) -> bool {
        self.release(block_key(chunk))
    }
}

/// An accepted upload request on its way to the writer of the connection.
pub(crate) struct UploadRequest {
    pub tx: UnboundedSender<WriterRequest>,
    pub chunk: ChunkInfo,
    pub gate: Arc<UploadGate>,
}

pub const DEFAULT_THROTTLED_UPLOAD_BPS: NonZeroU32 = match NonZeroU32::new(32 * 1024) {
    Some(v) => v,
    None => panic!("default throttled upload rate is zero"),
};

/// The session-wide rate shared by every connection that got [`PeerVerdict::Throttle`].
pub(crate) struct ThrottledUpload(Limits);

impl ThrottledUpload {
    pub fn new() -> Self {
        Self(Limits::new(LimitsConfig {
            upload_bps: Some(DEFAULT_THROTTLED_UPLOAD_BPS),
            download_bps: None,
        }))
    }

    pub fn set(&self, bps: Option<NonZeroU32>) {
        self.0.set_upload_bps(bps);
    }

    pub fn get(&self) -> Option<NonZeroU32> {
        self.0.get_upload_bps()
    }

    /// Waits until `len` bytes may be uploaded. A rate lower than a block size is fine: the
    /// wait is split in steps no bigger than one second worth of the rate.
    pub async fn acquire(&self, len: NonZeroU32) -> crate::Result<()> {
        let mut left = len.get();
        let mut stale_rate_retries = 0;
        while let Some(left_nz) = NonZeroU32::new(left) {
            let Some(bps) = self.0.get_upload_bps() else {
                return Ok(());
            };
            let step = left_nz.min(bps);
            match self.0.prepare_for_upload(step).await {
                Ok(()) => left -= step.get(),
                // The rate was lowered between reading it and waiting for it.
                Err(_) if stale_rate_retries < 3 => stale_rate_retries += 1,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Per-connection glue between the peer handler and the installed policy.
pub(crate) struct PeerPolicyBinding {
    policy: Option<Arc<dyn PeerPolicy>>,
    gate: Arc<UploadGate>,
    info_hash: Id20,
    addr: SocketAddr,
    private: bool,
    total_length: u64,
    piece_length: u32,
    num_pieces: u32,
    // The torrent has every selected piece. Kept up to date by the torrent.
    we_are_seeding: Arc<AtomicBool>,
    tx: UnboundedSender<WriterRequest>,
    // Disconnected is only reported for connections that got to report a handshake.
    established: AtomicBool,
}

impl PeerPolicyBinding {
    pub fn new(
        policy: Option<Arc<dyn PeerPolicy>>,
        info_hash: Id20,
        addr: SocketAddr,
        private: bool,
        lengths: &Lengths,
        we_are_seeding: Arc<AtomicBool>,
        tx: UnboundedSender<WriterRequest>,
    ) -> Self {
        Self {
            policy,
            gate: Default::default(),
            info_hash,
            addr: canonical_addr(addr),
            private,
            total_length: lengths.total_length(),
            piece_length: lengths.default_piece_length(),
            num_pieces: lengths.total_pieces(),
            we_are_seeding,
            tx,
            established: AtomicBool::new(false),
        }
    }

    pub fn is_active(&self) -> bool {
        self.policy.is_some()
    }

    pub fn gate(&self) -> &Arc<UploadGate> {
        &self.gate
    }

    pub fn num_pieces(&self) -> u32 {
        self.num_pieces
    }

    pub fn mark_established(&self) {
        self.established.store(true, Ordering::Release);
    }

    fn ctx(&self) -> PeerCtx<'_> {
        PeerCtx {
            info_hash: self.info_hash,
            addr: self.addr,
            private: self.private,
            total_length: self.total_length,
            piece_length: self.piece_length,
            num_pieces: self.num_pieces,
            we_are_seeding: self.we_are_seeding.load(Ordering::Acquire),
            _p: PhantomData,
        }
    }

    /// Reports the event and applies the verdict to the connection. An error means the
    /// connection has to be closed.
    pub fn dispatch(&self, event: PeerEvent<'_>) -> anyhow::Result<()> {
        let Some(policy) = self.policy.as_ref() else {
            return Ok(());
        };
        let verdict = policy.on_event(&self.ctx(), event);
        self.apply(verdict)
    }

    /// Reports the end of the connection, once, if it was established.
    pub fn disconnected(&self, bits: Option<&BitSlice<u8, Msb0>>) {
        let Some(policy) = self.policy.as_ref() else {
            return;
        };
        if !self.established.swap(false, Ordering::AcqRel) {
            return;
        }
        // By contract the verdict of this event is ignored.
        policy.on_event(&self.ctx(), PeerEvent::Disconnected { bits });
    }

    fn apply(&self, verdict: PeerVerdict) -> anyhow::Result<()> {
        if verdict <= self.gate.raise(verdict) {
            return Ok(());
        }
        match verdict {
            PeerVerdict::Allow | PeerVerdict::Throttle => Ok(()),
            PeerVerdict::Choke => {
                self.gate.drop_queued();
                if self
                    .tx
                    .send(WriterRequest::Message(Message::Choke))
                    .is_err()
                {
                    trace!(addr = %self.addr, "peer is gone, not sending choke");
                }
                Ok(())
            }
            PeerVerdict::Disconnect => {
                self.gate.drop_queued();
                anyhow::bail!("disconnected by peer policy")
            }
        }
    }
}

// The tasks of a connection are dropped without notice when the torrent is paused or removed or
// the session closes. The policy still hears that the connection is over, without a bitfield.
impl Drop for PeerPolicyBinding {
    fn drop(&mut self) {
        self.disconnected(None);
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use parking_lot::Mutex;
    use tokio::sync::mpsc::unbounded_channel;

    use super::*;

    fn lengths() -> Lengths {
        Lengths::new(100_000, 32 * 1024).unwrap()
    }

    #[derive(Default)]
    struct Recorder {
        events: Mutex<Vec<String>>,
        verdicts: Mutex<Vec<PeerVerdict>>,
    }

    impl PeerPolicy for Recorder {
        fn admit(&self, _ip: IpAddr) -> bool {
            true
        }
        fn on_event(&self, ctx: &PeerCtx<'_>, event: PeerEvent<'_>) -> PeerVerdict {
            self.events.lock().push(format!("{}:{:?}", ctx.addr, event));
            let mut v = self.verdicts.lock();
            if v.is_empty() {
                PeerVerdict::Allow
            } else {
                v.remove(0)
            }
        }
    }

    const CAP: u32 = MAX_QUEUED_UPLOADS_PER_PEER;

    fn binding(
        policy: Option<Arc<dyn PeerPolicy>>,
    ) -> (
        PeerPolicyBinding,
        tokio::sync::mpsc::UnboundedReceiver<WriterRequest>,
    ) {
        let (tx, rx) = unbounded_channel();
        (
            PeerPolicyBinding::new(
                policy,
                Id20::new([7; 20]),
                "[::ffff:1.2.3.4]:6881".parse().unwrap(),
                false,
                &lengths(),
                Arc::new(AtomicBool::new(false)),
                tx,
            ),
            rx,
        )
    }

    #[test]
    fn verdicts_are_ordered_by_severity() {
        use PeerVerdict::*;
        assert!(Allow < Throttle && Throttle < Choke && Choke < Disconnect);
        for v in [Allow, Throttle, Choke, Disconnect] {
            assert_eq!(PeerVerdict::from_u8(v as u8), v);
        }
    }

    #[test]
    fn ipv4_mapped_addresses_are_normalized() {
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        assert_eq!(canonical_ip(mapped), "10.1.2.3".parse::<IpAddr>().unwrap());
        // Not mapped: left alone.
        for s in [
            "2001:db8::1",
            "::1",
            "::10.1.2.3",
            "64:ff9b::1.2.3.4",
            "1.2.3.4",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert_eq!(canonical_ip(ip), ip, "{s}");
        }
        let addr: SocketAddr = "[::ffff:1.2.3.4]:51413".parse().unwrap();
        assert_eq!(
            canonical_addr(addr),
            "1.2.3.4:51413".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn gate_cancel_drops_exactly_the_cancelled_request() {
        let g = UploadGate::default();
        let k = (3, 0, 16384);
        assert!(g.register(k, CAP));
        g.cancel(k);
        assert!(!g.release(k), "cancelled request must not be served");
        // The same block asked for again later is served.
        assert!(g.register(k, CAP));
        assert!(g.release(k));
    }

    #[test]
    fn gate_cancel_without_pending_request_is_forgotten() {
        let g = UploadGate::default();
        let k = (3, 0, 16384);
        g.cancel(k);
        g.register(k, CAP);
        assert!(
            g.release(k),
            "a stray cancel must not swallow a later request"
        );
        // Also when other requests are waiting.
        g.register((1, 0, 16384), CAP);
        g.cancel(k);
        g.register(k, CAP);
        assert!(g.release(k));
    }

    #[test]
    fn gate_cancel_after_release_is_forgotten() {
        let g = UploadGate::default();
        let k = (1, 16384, 16384);
        g.register(k, CAP);
        assert!(g.release(k));
        g.cancel(k);
        g.register(k, CAP);
        assert!(g.release(k));
    }

    #[test]
    fn gate_duplicate_requests_are_cancelled_one_by_one() {
        let g = UploadGate::default();
        let k = (0, 0, 16384);
        g.register(k, CAP);
        g.register(k, CAP);
        g.cancel(k);
        g.cancel(k);
        g.cancel(k); // more cancels than requests: capped
        assert!(!g.release(k));
        assert!(!g.release(k));
        g.register(k, CAP);
        assert!(g.release(k));
    }

    #[test]
    fn gate_cancel_of_one_duplicate_keeps_the_other() {
        let g = UploadGate::default();
        let k = (0, 0, 16384);
        g.register(k, CAP);
        g.register(k, CAP);
        g.cancel(k);
        assert!(!g.release(k));
        assert!(g.release(k));
    }

    #[test]
    fn gate_cancel_does_not_touch_other_blocks() {
        let g = UploadGate::default();
        g.register((0, 0, 16384), CAP);
        g.register((0, 16384, 16384), CAP);
        g.cancel((0, 0, 16384));
        assert!(g.release((0, 16384, 16384)));
        assert!(!g.release((0, 0, 16384)));
    }

    #[test]
    fn gate_bounds_the_requests_waiting_per_connection() {
        let g = UploadGate::default();
        for i in 0..3 {
            assert!(g.register((i, 0, 16384), 3));
        }
        assert!(!g.register((9, 0, 16384), 3), "over the limit: ignored");
        assert!(!g.register((0, 0, 16384), 3), "also for a duplicate");
        // The ignored ones left no trace.
        assert!(g.release((0, 0, 16384)));
        assert!(g.register((9, 0, 16384), 3), "a slot is free again");
        assert!(g.release((9, 0, 16384)));
        assert!(g.release((1, 0, 16384)));
        assert!(g.release((2, 0, 16384)));
        assert_eq!(g.queued.load(Ordering::Relaxed), 0);
        assert_eq!(g.cancelled.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn gate_counts_stay_in_step_with_cancels_and_releases() {
        let g = UploadGate::default();
        g.register((0, 0, 16384), CAP);
        g.register((1, 0, 16384), CAP);
        g.cancel((1, 0, 16384));
        assert_eq!(g.queued.load(Ordering::Relaxed), 2);
        assert_eq!(g.cancelled.load(Ordering::Relaxed), 1);
        assert!(!g.release((1, 0, 16384)));
        assert_eq!(g.cancelled.load(Ordering::Relaxed), 0);
        assert!(g.release((0, 0, 16384)));
        assert_eq!(g.queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn gate_choke_drops_everything_queued_and_everything_later() {
        let (b, _rx) = binding(Some(Arc::new(Recorder::default())));
        let g = b.gate().clone();
        g.register((0, 0, 16384), CAP);
        g.register((1, 0, 16384), CAP);
        b.apply(PeerVerdict::Choke).unwrap();
        assert!(!g.release((0, 0, 16384)));
        assert!(!g.release((1, 0, 16384)));
        // A request that raced the choke is dropped as well.
        g.register((2, 0, 16384), CAP);
        assert!(!g.release((2, 0, 16384)));
        assert_eq!(g.queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn keep_drops_and_releases_dropped_requests() {
        let g = UploadGate::default();
        let (index, offset, size) = (0, 0, 16384);
        let chunk = lengths()
            .chunk_info_from_received_data(
                lengths().validate_piece_index(index).unwrap(),
                offset,
                size,
            )
            .unwrap();
        g.register(block_key(&chunk), CAP);
        assert!(g.keep(&chunk));
        g.cancel(block_key(&chunk));
        assert!(!g.keep(&chunk));
        assert_eq!(g.queued.load(Ordering::Relaxed), 0);
        // Nothing left for the writer to trip over.
        g.register(block_key(&chunk), CAP);
        assert!(g.should_upload(&chunk));
    }

    #[test]
    fn verdicts_are_sticky_and_only_act_once() {
        let (b, mut rx) = binding(Some(Arc::new(Recorder::default())));
        b.apply(PeerVerdict::Throttle).unwrap();
        assert_eq!(b.gate().level(), PeerVerdict::Throttle);
        b.apply(PeerVerdict::Choke).unwrap();
        assert!(matches!(
            rx.try_recv(),
            Ok(WriterRequest::Message(Message::Choke))
        ));
        // Milder or equal verdicts neither downgrade nor choke again.
        b.apply(PeerVerdict::Allow).unwrap();
        b.apply(PeerVerdict::Throttle).unwrap();
        b.apply(PeerVerdict::Choke).unwrap();
        assert_eq!(b.gate().level(), PeerVerdict::Choke);
        assert!(rx.try_recv().is_err(), "choke must be sent exactly once");
        // Disconnect escalates from choke, and is an error for the caller.
        assert!(b.apply(PeerVerdict::Disconnect).is_err());
        assert_eq!(b.gate().level(), PeerVerdict::Disconnect);
    }

    #[test]
    fn dispatch_without_policy_does_nothing() {
        let (b, mut rx) = binding(None);
        assert!(!b.is_active());
        b.dispatch(PeerEvent::Have { piece: 1 }).unwrap();
        assert_eq!(b.gate().level(), PeerVerdict::Allow);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn dispatch_reports_normalized_context_and_applies_the_verdict() {
        let rec = Arc::new(Recorder::default());
        rec.verdicts
            .lock()
            .extend([PeerVerdict::Allow, PeerVerdict::Disconnect]);
        let (b, _rx) = binding(Some(rec.clone()));
        b.dispatch(PeerEvent::Have { piece: 4 }).unwrap();
        assert!(b.dispatch(PeerEvent::Have { piece: 5 }).is_err());
        let events = rec.events.lock();
        assert_eq!(events.len(), 2);
        assert!(events[0].starts_with("1.2.3.4:6881:"), "{}", events[0]);
    }

    #[test]
    fn context_describes_the_torrent() {
        let (b, _rx) = binding(None);
        let ctx = b.ctx();
        assert_eq!(ctx.total_length, 100_000);
        assert_eq!(ctx.piece_length, 32 * 1024);
        assert_eq!(ctx.num_pieces, 4);
        assert!(!ctx.we_are_seeding);
        b.we_are_seeding.store(true, Ordering::Release);
        assert!(b.ctx().we_are_seeding, "follows the torrent");
        assert!(!ctx.private);
        assert_eq!(ctx.addr, "1.2.3.4:6881".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn disconnected_is_reported_once_and_only_when_established() {
        let rec = Arc::new(Recorder::default());
        let (b, _rx) = binding(Some(rec.clone()));
        b.disconnected(None);
        assert!(rec.events.lock().is_empty(), "never handshaken");
        b.mark_established();
        b.disconnected(None);
        b.disconnected(None);
        assert_eq!(rec.events.lock().len(), 1);
        assert!(rec.events.lock()[0].contains("Disconnected"));
        // Dropping afterwards doesn't report it again.
        drop(b);
        assert_eq!(rec.events.lock().len(), 1);
    }

    #[test]
    fn dropping_an_established_binding_reports_disconnected() {
        let rec = Arc::new(Recorder::default());
        let (b, _rx) = binding(Some(rec.clone()));
        drop(b);
        assert!(rec.events.lock().is_empty(), "never handshaken");

        let (b, _rx) = binding(Some(rec.clone()));
        b.mark_established();
        drop(b);
        assert_eq!(rec.events.lock().len(), 1);
        assert!(rec.events.lock()[0].contains("Disconnected { bits: None }"));
    }

    #[test]
    fn disconnected_verdict_is_ignored() {
        let rec = Arc::new(Recorder::default());
        rec.verdicts.lock().push(PeerVerdict::Disconnect);
        let (b, mut rx) = binding(Some(rec));
        b.mark_established();
        b.disconnected(None);
        assert_eq!(b.gate().level(), PeerVerdict::Allow);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn throttled_upload_waits_for_the_configured_rate() {
        let t = ThrottledUpload::new();
        assert_eq!(t.get(), Some(DEFAULT_THROTTLED_UPLOAD_BPS));
        assert_eq!(DEFAULT_THROTTLED_UPLOAD_BPS.get(), 32 * 1024);
        t.set(NonZeroU32::new(64 * 1024));
        let block = NonZeroU32::new(16 * 1024).unwrap();

        // The first second worth of bytes is a burst.
        let start = Instant::now();
        for _ in 0..4 {
            t.acquire(block).await.unwrap();
        }
        assert!(start.elapsed() < Duration::from_millis(300));

        // After that blocks come at the configured rate: 4 blocks = 1s.
        let start = Instant::now();
        for _ in 0..4 {
            t.acquire(block).await.unwrap();
        }
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(700), "{took:?}");
        assert!(took < Duration::from_secs(3), "{took:?}");
    }

    #[tokio::test]
    async fn throttled_upload_handles_rates_lower_than_a_block() {
        let t = ThrottledUpload::new();
        t.set(NonZeroU32::new(8 * 1024));
        let start = Instant::now();
        t.acquire(NonZeroU32::new(16 * 1024).unwrap())
            .await
            .expect("a block bigger than the burst must not be an error");
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(700), "{took:?}");
        assert!(took < Duration::from_secs(4), "{took:?}");
    }

    #[tokio::test]
    async fn throttled_upload_without_a_rate_does_not_wait() {
        let t = ThrottledUpload::new();
        t.set(None);
        assert_eq!(t.get(), None);
        let start = Instant::now();
        for _ in 0..64 {
            t.acquire(NonZeroU32::new(16 * 1024).unwrap())
                .await
                .unwrap();
        }
        assert!(start.elapsed() < Duration::from_millis(300));
    }
}
