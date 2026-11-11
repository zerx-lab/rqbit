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
    time::Instant,
};

use bitvec::{order::Msb0, slice::BitSlice};
use librqbit_core::{
    hash_id::Id20,
    lengths::{ChunkInfo, Lengths},
};
use parking_lot::Mutex;
use peer_binary_protocol::{Message, Request};
use tokio::sync::mpsc::UnboundedSender;

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
    /// (it has no upload slot, or the policy choked it; the request is then ignored).
    /// `peer_claims_piece` tells whether the peer had announced the piece through its bitfield
    /// or a HAVE before asking for it.
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
pub(crate) type BlockKey = (u32, u32, u32);

fn block_key(chunk: &ChunkInfo) -> BlockKey {
    (chunk.piece_index.get(), chunk.offset, chunk.size)
}

#[derive(Default)]
struct PendingBlock {
    queued: u32,
    cancelled: u32,
    // An allowed-fast request (BEP 6): a choke does not drop it, it is served while the peer
    // is choked.
    exempt: bool,
}

#[derive(Default)]
struct GateBlocks {
    blocks: HashMap<BlockKey, PendingBlock>,
    // Sums over `blocks`.
    queued: u32,
    cancelled: u32,
    // We unchoked the peer. A connection starts choked (BEP 3).
    unchoked: bool,
    // When we last choked the peer, for the reject grace (`fast::CHOKE_REJECT_GRACE`).
    choked_at: Option<Instant>,
    // Requests turned down on arrival since the last choke, unchoke or served block, outside
    // of the grace (see `fast::MAX_REJECTS_PER_CHOKE`).
    rejects: u32,
    // The allowed-fast set we offered the peer (BEP 6), and its blocks served while choked.
    // Under the same lock as the queue, so accepting a request past the choke is one decision.
    fast_upload: crate::fast::FastUpload,
}

/// How many accepted upload requests may wait for one connection. Requests above it are
/// ignored; the peer asks again for what it didn't get. The limit is announced as `reqq`.
pub(crate) const MAX_QUEUED_UPLOADS_PER_PEER: u32 = 500;
/// The same for a throttled connection: the throttled queue is shared and slow, a few blocks per
/// connection keep its memory bounded and let throttled peers take turns.
pub(crate) const MAX_QUEUED_THROTTLED_UPLOADS_PER_PEER: u32 = 4;

/// Shared between the reader side of a connection (which registers requests and cancels), the
/// choker, the upload schedulers and the writer: it knows which accepted upload requests must
/// still be served. A request is dropped when the peer cancelled it, or when the connection
/// was choked (it lost its upload slot, or the policy choked or disconnected it). With the Fast
/// Extension the caller rejects what a choke dropped; allowed-fast requests are exempt and stay
/// queued.
#[derive(Default)]
pub(crate) struct UploadGate {
    level: AtomicU8,
    // Copies of the sums in `pending`, so that the common cases (nothing waits, nothing was
    // cancelled) are decided without taking the lock.
    queued: AtomicU32,
    cancelled: AtomicU32,
    pending: Mutex<GateBlocks>,
    // Both handshakes carried the Fast Extension bit (BEP 6). Set once, at the handshake.
    fast: AtomicBool,
}

/// What [`UploadGate::register_fast`] did with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Registered {
    /// Queued: the peer is unchoked.
    Queued,
    /// Queued past the choke, as an allowed-fast request.
    QueuedAllowedFast,
    /// Not queued: the peer is choked.
    Choked,
    /// Not queued: as many requests of the connection as allowed wait already.
    Full,
}

impl UploadGate {
    pub fn level(&self) -> PeerVerdict {
        PeerVerdict::from_u8(self.level.load(Ordering::Acquire))
    }

    /// Escalates the connection's verdict. Returns the previous one.
    fn raise(&self, to: PeerVerdict) -> PeerVerdict {
        PeerVerdict::from_u8(self.level.fetch_max(to as u8, Ordering::AcqRel))
    }

    /// Whether the choker (or the policy) currently allows this peer an upload slot.
    pub fn is_unchoked(&self) -> bool {
        self.pending.lock().unchoked
    }

    /// Records that the Fast Extension was negotiated on the connection.
    pub fn set_fast(&self, fast: bool) {
        self.fast.store(fast, Ordering::Release);
    }

    /// Whether the Fast Extension was negotiated on the connection: the peer then expects a
    /// `RejectRequest` for every request we will not serve.
    pub fn is_fast(&self) -> bool {
        self.fast.load(Ordering::Acquire)
    }

    /// Takes one reject for a request turned down on arrival (BEP 6). Within
    /// [`CHOKE_REJECT_GRACE`](crate::fast::CHOKE_REJECT_GRACE) of our last choke every such
    /// request is rejected: the peer sent it before the choke reached it. Otherwise at most
    /// [`MAX_REJECTS_PER_CHOKE`](crate::fast::MAX_REJECTS_PER_CHOKE) are rejected between two
    /// chokes, unchokes or served blocks. `false`: the peer keeps asking for what it is
    /// refused; BEP 6 wants every request answered, so the connection is to be closed rather
    /// than the request dropped.
    pub fn take_reject(&self, now: Instant) -> bool {
        let mut g = self.pending.lock();
        if g.choked_at
            .is_some_and(|at| now.saturating_duration_since(at) < crate::fast::CHOKE_REJECT_GRACE)
        {
            return true;
        }
        g.rejects = g.rejects.saturating_add(1);
        g.rejects <= crate::fast::MAX_REJECTS_PER_CHOKE
    }

    /// The peer asked for the block. `false`: the request is ignored, because the peer is
    /// choked or `max_queued` requests of the connection already wait.
    pub fn register(&self, key: BlockKey, max_queued: u32) -> bool {
        let mut g = self.pending.lock();
        if !g.unchoked || g.queued >= max_queued {
            return false;
        }
        g.blocks.entry(key).or_default().queued += 1;
        g.queued += 1;
        self.queued.store(g.queued, Ordering::Release);
        true
    }

    /// [`UploadGate::register`] for a connection with the Fast Extension (BEP 6), which needs
    /// to know why a request was not accepted to answer it. A block of a piece in the
    /// allowed-fast set we offered the peer is accepted while the peer is choked too, once per
    /// block and only while the policy has nothing against the peer (it bypasses the choke,
    /// not the queue bound), and a later choke does not drop it.
    pub fn register_fast(&self, key: BlockKey, max_queued: u32) -> Registered {
        let mut g = self.pending.lock();
        if g.queued >= max_queued {
            return Registered::Full;
        }
        let offered = g.fast_upload.is_offered(key.0);
        let unchoked = g.unchoked;
        if !unchoked
            && !(offered && self.level() == PeerVerdict::Allow && g.fast_upload.take_block(key))
        {
            return Registered::Choked;
        }
        let b = g.blocks.entry(key).or_default();
        b.queued += 1;
        b.exempt |= offered;
        g.queued += 1;
        self.queued.store(g.queued, Ordering::Release);
        if unchoked {
            Registered::Queued
        } else {
            Registered::QueuedAllowedFast
        }
    }

    /// Whether we already decided which allowed-fast set to offer the peer.
    pub fn allowed_fast_decided(&self) -> bool {
        self.pending.lock().fast_upload.decided()
    }

    /// Records the allowed-fast set offered to the peer (possibly empty); decided once.
    pub fn offer_allowed_fast(&self, pieces: Vec<u32>) {
        self.pending.lock().fast_upload.set_offered(pieces);
    }

    /// We choke or unchoke the peer. A choke drops every request that waits, except
    /// allowed-fast ones while the policy has nothing against the peer (a policy choke or
    /// disconnect drops them too). On a connection with the Fast Extension the dropped ones are
    /// returned (one entry per request still to be served) so the caller can reject each of
    /// them; a request the peer already cancelled is not returned, it was answered when the
    /// cancel arrived. Without the extension nothing is returned: the peer asks again once it is
    /// unchoked.
    pub fn set_choked(&self, choked: bool) -> Vec<BlockKey> {
        let mut g = self.pending.lock();
        self.choke_locked(&mut g, choked, Instant::now())
    }

    /// [`UploadGate::set_choked`] for the choker: also queues the `Choke` or `Unchoke` for the
    /// peer and, on a Fast connection, a `RejectRequest` for every request the choke dropped,
    /// all under the gate lock. A request turned down on arrival because of the choke is
    /// rejected only after its registration released that lock, so the peer always reads the
    /// `Choke` before such a reject. Returns `false` when the peer is gone.
    pub fn announce_choked(&self, choked: bool, tx: &UnboundedSender<WriterRequest>) -> bool {
        let mut g = self.pending.lock();
        let dropped = self.choke_locked(&mut g, choked, Instant::now());
        let msg = if choked {
            Message::Choke
        } else {
            Message::Unchoke
        };
        tx.send(WriterRequest::Message(msg)).is_ok() && send_rejects(tx, dropped)
    }

    /// After a policy `Choke`: drops every request that waits, allowed-fast ones included, and
    /// rejects each of them on a Fast connection. The choker only acts on a peer whose slot
    /// state changes, so without this the allowed-fast requests of a peer that held no slot
    /// would still be served. Returns `false` when the peer is gone.
    pub fn drop_all(&self, tx: &UnboundedSender<WriterRequest>) -> bool {
        let mut g = self.pending.lock();
        let dropped = self.drop_blocks(&mut g, |_| true);
        send_rejects(tx, dropped)
    }

    fn choke_locked(&self, g: &mut GateBlocks, choked: bool, now: Instant) -> Vec<BlockKey> {
        g.unchoked = !choked;
        g.rejects = 0;
        if !choked {
            return Vec::new();
        }
        g.choked_at = Some(now);
        let keep_exempt = self.level() == PeerVerdict::Allow;
        self.drop_blocks(g, |b| !(keep_exempt && b.exempt))
    }

    fn drop_blocks(
        &self,
        g: &mut GateBlocks,
        drop: impl Fn(&PendingBlock) -> bool,
    ) -> Vec<BlockKey> {
        // Only a Fast connection answers what was dropped; the others need no list.
        let collect = self.is_fast();
        let mut dropped = Vec::new();
        g.blocks.retain(|key, b| {
            if !drop(b) {
                return true;
            }
            if collect {
                let live = b.queued.saturating_sub(b.cancelled);
                dropped.extend(std::iter::repeat_n(*key, live as usize));
            }
            false
        });
        g.queued = g.blocks.values().map(|b| b.queued).sum();
        g.cancelled = g.blocks.values().map(|b| b.cancelled).sum();
        self.queued.store(g.queued, Ordering::Release);
        self.cancelled.store(g.cancelled, Ordering::Release);
        dropped
    }

    /// The peer cancelled the block. Only cancels a request that is still waiting: one that
    /// was already sent (or never made) has nothing to cancel, and remembering the cancel would
    /// swallow a later legitimate request for the same block. Returns whether a waiting request
    /// was cancelled, so a Fast connection can answer it with `RejectRequest`.
    pub fn cancel(&self, key: BlockKey) -> bool {
        if self.queued.load(Ordering::Acquire) == 0 {
            return false;
        }
        let mut g = self.pending.lock();
        if let Some(b) = g.blocks.get_mut(&key)
            && b.cancelled < b.queued
        {
            b.cancelled += 1;
            g.cancelled += 1;
            self.cancelled.store(g.cancelled, Ordering::Release);
            return true;
        }
        false
    }

    /// Takes one waiting request for the block out of the queue. Returns whether it has to be
    /// served: it does not when it was cancelled, or dropped by a choke.
    pub fn release(&self, key: BlockKey) -> bool {
        if self.queued.load(Ordering::Acquire) == 0 {
            return false;
        }
        let mut g = self.pending.lock();
        let Some(b) = g.blocks.get_mut(&key) else {
            return false;
        };
        b.queued -= 1;
        let cancelled = b.cancelled > 0;
        if cancelled {
            b.cancelled -= 1;
        }
        if b.queued == 0 {
            g.blocks.remove(&key);
        }
        g.queued -= 1;
        if cancelled {
            g.cancelled -= 1;
        } else {
            // The peer is being served: what it asked for before is no flood.
            g.rejects = 0;
        }
        self.queued.store(g.queued, Ordering::Release);
        self.cancelled.store(g.cancelled, Ordering::Release);
        !cancelled
    }

    /// For schedulers: `false` means the request is not to be served (and is released, if it
    /// was cancelled).
    pub fn keep(&self, chunk: &ChunkInfo) -> bool {
        let key = block_key(chunk);
        if self.queued.load(Ordering::Acquire) == 0 {
            return false;
        }
        let cancelled = match self.pending.lock().blocks.get(&key) {
            Some(b) => b.cancelled > 0,
            None => return false,
        };
        if cancelled {
            self.release(key);
        }
        !cancelled
    }

    /// For the writer, right before it reads the block from disk: takes the request out of the
    /// queue and tells whether it still has to be served.
    pub fn should_upload(&self, chunk: &ChunkInfo) -> bool {
        self.release(block_key(chunk))
    }
}

/// Queues a `RejectRequest` for each block. `false`: the peer is gone.
fn send_rejects(tx: &UnboundedSender<WriterRequest>, blocks: Vec<BlockKey>) -> bool {
    blocks.into_iter().all(|(index, begin, length)| {
        tx.send(WriterRequest::Message(Message::RejectRequest(Request {
            index,
            begin,
            length,
        })))
        .is_ok()
    })
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
    /// block is let through in parts of one second worth of the rate.
    pub async fn acquire(&self, len: NonZeroU32) -> crate::Result<()> {
        self.0.prepare_for_upload(len).await
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

    /// Reports the event and raises the connection to the verdict. Returns the verdict when it
    /// is a new one for the connection: [`PeerVerdict::Throttle`] and [`PeerVerdict::Choke`] are
    /// then for the caller to carry out. An error means the connection has to be closed.
    pub fn dispatch(&self, event: PeerEvent<'_>) -> anyhow::Result<Option<PeerVerdict>> {
        let Some(policy) = self.policy.as_ref() else {
            return Ok(None);
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

    fn apply(&self, verdict: PeerVerdict) -> anyhow::Result<Option<PeerVerdict>> {
        if verdict <= self.gate.raise(verdict) {
            return Ok(None);
        }
        if verdict == PeerVerdict::Disconnect {
            // Nothing that still waits goes out while the connection is taken down.
            self.gate.set_choked(true);
            anyhow::bail!("disconnected by peer policy")
        }
        Ok(Some(verdict))
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

    fn binding(policy: Option<Arc<dyn PeerPolicy>>) -> PeerPolicyBinding {
        PeerPolicyBinding::new(
            policy,
            Id20::new([7; 20]),
            "[::ffff:1.2.3.4]:6881".parse().unwrap(),
            false,
            &lengths(),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn unchoked() -> UploadGate {
        let g = UploadGate::default();
        g.set_choked(false);
        g
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
        let g = unchoked();
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
        let g = unchoked();
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
        let g = unchoked();
        let k = (1, 16384, 16384);
        g.register(k, CAP);
        assert!(g.release(k));
        g.cancel(k);
        g.register(k, CAP);
        assert!(g.release(k));
    }

    #[test]
    fn gate_duplicate_requests_are_cancelled_one_by_one() {
        let g = unchoked();
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
        let g = unchoked();
        let k = (0, 0, 16384);
        g.register(k, CAP);
        g.register(k, CAP);
        g.cancel(k);
        assert!(!g.release(k));
        assert!(g.release(k));
    }

    #[test]
    fn gate_cancel_does_not_touch_other_blocks() {
        let g = unchoked();
        g.register((0, 0, 16384), CAP);
        g.register((0, 16384, 16384), CAP);
        g.cancel((0, 0, 16384));
        assert!(g.release((0, 16384, 16384)));
        assert!(!g.release((0, 0, 16384)));
    }

    #[test]
    fn gate_bounds_the_requests_waiting_per_connection() {
        let g = unchoked();
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
        let g = unchoked();
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
    fn gate_ignores_the_requests_of_a_choked_peer() {
        let g = UploadGate::default();
        let k = (0, 0, 16384);
        assert!(!g.register(k, CAP), "a connection starts choked");
        assert!(!g.release(k));
        g.set_choked(false);
        assert!(g.register(k, CAP));
        assert!(g.release(k));
    }

    #[test]
    fn gate_choke_drops_what_waits_and_a_block_asked_for_again_is_sent_once() {
        let chunk = lengths()
            .chunk_info_from_received_data(lengths().validate_piece_index(0).unwrap(), 0, 16384)
            .unwrap();
        let k = block_key(&chunk);
        let g = unchoked();
        assert!(g.register(k, CAP));
        assert!(g.register((1, 0, 16384), CAP));
        g.cancel((1, 0, 16384));
        g.set_choked(true);
        assert_eq!(g.queued.load(Ordering::Relaxed), 0);
        assert_eq!(g.cancelled.load(Ordering::Relaxed), 0);
        assert!(
            !g.keep(&chunk),
            "the scheduler skips what the choke dropped"
        );
        assert!(!g.register(k, CAP));

        // Unchoked again, the peer repeats the request while the old one is still on its way
        // to the writer: the block goes out for one of them only.
        g.set_choked(false);
        assert!(g.register(k, CAP));
        assert!(g.keep(&chunk));
        assert!(g.should_upload(&chunk));
        assert!(!g.should_upload(&chunk));
    }

    #[test]
    fn keep_drops_and_releases_dropped_requests() {
        let g = unchoked();
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

    fn fast_unchoked() -> UploadGate {
        let g = unchoked();
        g.set_fast(true);
        g
    }

    /// The blocks of the `RejectRequest`s queued on the channel, in order.
    fn rejects_sent(rx: &mut tokio::sync::mpsc::UnboundedReceiver<WriterRequest>) -> Vec<BlockKey> {
        let mut out = Vec::new();
        while let Ok(req) = rx.try_recv() {
            if let WriterRequest::Message(Message::RejectRequest(r)) = req {
                out.push((r.index, r.begin, r.length));
            }
        }
        out
    }

    #[test]
    fn fast_choke_returns_each_live_request_once() {
        let g = fast_unchoked();
        let a = (0, 0, 16384);
        let b = (0, 16384, 16384);
        let c = (1, 0, 16384);
        // Asked twice: two requests, two answers.
        assert_eq!(g.register_fast(a, CAP), Registered::Queued);
        assert_eq!(g.register_fast(a, CAP), Registered::Queued);
        assert_eq!(g.register_fast(b, CAP), Registered::Queued);
        // Cancelled: answered when the cancel arrived, not again.
        assert_eq!(g.register_fast(c, CAP), Registered::Queued);
        assert!(g.cancel(c));
        let mut dropped = g.set_choked(true);
        dropped.sort();
        assert_eq!(dropped, vec![a, a, b]);
        assert_eq!(g.queued.load(Ordering::Relaxed), 0);
        assert_eq!(g.cancelled.load(Ordering::Relaxed), 0);
        // An unchoke drops nothing.
        assert!(g.set_choked(false).is_empty());
    }

    #[test]
    fn choke_without_fast_returns_nothing() {
        let g = unchoked();
        assert!(g.register((0, 0, 16384), CAP));
        assert!(g.set_choked(true).is_empty());
        assert_eq!(g.queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn fast_register_tells_why_a_request_was_not_queued() {
        let g = fast_unchoked();
        for begin in 0..CAP {
            assert_eq!(g.register_fast((2, begin, 1), CAP), Registered::Queued);
        }
        assert_eq!(g.register_fast((3, 0, 16384), CAP), Registered::Full);
        g.set_choked(true);
        assert_eq!(g.register_fast((3, 0, 16384), CAP), Registered::Choked);
    }

    #[test]
    fn allowed_fast_blocks_bypass_the_choke_once_and_survive_it() {
        let g = UploadGate::default();
        g.set_fast(true);
        g.offer_allowed_fast(vec![2]);
        assert!(g.allowed_fast_decided());
        let k = (2, 0, 16384);
        assert_eq!(g.register_fast(k, CAP), Registered::QueuedAllowedFast);
        assert_eq!(
            g.register_fast((3, 0, 16384), CAP),
            Registered::Choked,
            "not in the set"
        );
        // A choke (we were choked already: the choker re-chokes on a rechoke) keeps it.
        assert!(g.set_choked(true).is_empty());
        assert_eq!(g.queued.load(Ordering::Relaxed), 1);
        let chunk = lengths()
            .chunk_info_from_received_data(lengths().validate_piece_index(2).unwrap(), 0, 16384)
            .unwrap();
        assert!(g.should_upload(&chunk));
        assert_eq!(
            g.register_fast(k, CAP),
            Registered::Choked,
            "a block of the set is served once while choked"
        );
    }

    #[test]
    fn allowed_fast_blocks_need_a_clean_verdict() {
        let g = UploadGate::default();
        g.set_fast(true);
        g.offer_allowed_fast(vec![5]);
        assert_eq!(
            g.register_fast((5, 0, 16384), CAP),
            Registered::QueuedAllowedFast
        );
        g.raise(PeerVerdict::Throttle);
        assert_eq!(
            g.register_fast((5, 16384, 16384), CAP),
            Registered::Choked,
            "a throttled peer does not get past the choke"
        );
        // Nor does what it queued before survive the next choke.
        assert_eq!(g.set_choked(true), vec![(5, 0, 16384)]);
    }

    #[test]
    fn announce_choked_queues_the_choke_before_its_rejects() {
        let g = fast_unchoked();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        assert_eq!(g.register_fast((0, 0, 16384), CAP), Registered::Queued);
        assert!(g.announce_choked(true, &tx));
        assert!(matches!(
            rx.try_recv(),
            Ok(WriterRequest::Message(Message::Choke))
        ));
        assert_eq!(rejects_sent(&mut rx), vec![(0, 0, 16384)]);
        assert!(g.announce_choked(false, &tx));
        assert!(matches!(
            rx.try_recv(),
            Ok(WriterRequest::Message(Message::Unchoke))
        ));
        drop(rx);
        assert!(!g.announce_choked(true, &tx), "the peer is gone");
    }

    #[test]
    fn drop_all_rejects_allowed_fast_requests_too() {
        let g = UploadGate::default();
        g.set_fast(true);
        g.offer_allowed_fast(vec![5]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        assert_eq!(
            g.register_fast((5, 0, 16384), CAP),
            Registered::QueuedAllowedFast
        );
        assert!(g.drop_all(&tx));
        assert_eq!(rejects_sent(&mut rx), vec![(5, 0, 16384)]);
        assert_eq!(g.queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rejects_on_arrival_are_unbounded_right_after_a_choke_then_capped() {
        let g = fast_unchoked();
        let t0 = Instant::now();
        g.choke_locked(&mut g.pending.lock(), true, t0);
        for _ in 0..crate::fast::MAX_REJECTS_PER_CHOKE * 2 {
            assert!(g.take_reject(t0), "in transit before the choke");
        }
        let later = t0 + crate::fast::CHOKE_REJECT_GRACE;
        for _ in 0..crate::fast::MAX_REJECTS_PER_CHOKE {
            assert!(g.take_reject(later));
        }
        assert!(!g.take_reject(later), "past the cap");
        // An unchoke starts the budget over.
        g.choke_locked(&mut g.pending.lock(), false, later);
        assert!(g.take_reject(later));
    }

    #[test]
    fn verdicts_are_sticky_and_only_act_once() {
        use PeerVerdict::*;
        let b = binding(Some(Arc::new(Recorder::default())));
        assert_eq!(b.apply(Throttle).unwrap(), Some(Throttle));
        assert_eq!(b.apply(Choke).unwrap(), Some(Choke));
        // Milder or equal verdicts neither downgrade nor act again.
        for v in [Allow, Throttle, Choke] {
            assert_eq!(b.apply(v).unwrap(), None);
        }
        assert_eq!(b.gate().level(), Choke);
        // Disconnect escalates from choke, and is an error for the caller.
        assert!(b.apply(Disconnect).is_err());
        assert_eq!(b.gate().level(), Disconnect);
    }

    #[test]
    fn disconnect_drops_what_waits() {
        let b = binding(Some(Arc::new(Recorder::default())));
        let g = b.gate().clone();
        g.set_choked(false);
        assert!(g.register((0, 0, 16384), CAP));
        assert!(b.apply(PeerVerdict::Disconnect).is_err());
        assert!(!g.release((0, 0, 16384)));
        assert!(!g.register((1, 0, 16384), CAP));
    }

    #[test]
    fn dispatch_without_policy_does_nothing() {
        let b = binding(None);
        assert!(!b.is_active());
        assert_eq!(b.dispatch(PeerEvent::Have { piece: 1 }).unwrap(), None);
        assert_eq!(b.gate().level(), PeerVerdict::Allow);
    }

    #[test]
    fn dispatch_reports_normalized_context_and_applies_the_verdict() {
        let rec = Arc::new(Recorder::default());
        rec.verdicts
            .lock()
            .extend([PeerVerdict::Allow, PeerVerdict::Disconnect]);
        let b = binding(Some(rec.clone()));
        b.dispatch(PeerEvent::Have { piece: 4 }).unwrap();
        assert!(b.dispatch(PeerEvent::Have { piece: 5 }).is_err());
        let events = rec.events.lock();
        assert_eq!(events.len(), 2);
        assert!(events[0].starts_with("1.2.3.4:6881:"), "{}", events[0]);
    }

    #[test]
    fn context_describes_the_torrent() {
        let b = binding(None);
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
        let b = binding(Some(rec.clone()));
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
        let b = binding(Some(rec.clone()));
        drop(b);
        assert!(rec.events.lock().is_empty(), "never handshaken");

        let b = binding(Some(rec.clone()));
        b.mark_established();
        drop(b);
        assert_eq!(rec.events.lock().len(), 1);
        assert!(rec.events.lock()[0].contains("Disconnected { bits: None }"));
    }

    #[test]
    fn disconnected_verdict_is_ignored() {
        let rec = Arc::new(Recorder::default());
        rec.verdicts.lock().push(PeerVerdict::Disconnect);
        let b = binding(Some(rec));
        b.mark_established();
        b.disconnected(None);
        assert_eq!(b.gate().level(), PeerVerdict::Allow);
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
