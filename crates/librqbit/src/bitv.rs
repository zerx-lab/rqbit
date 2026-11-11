use std::path::PathBuf;

use anyhow::Context;
use bitvec::{boxed::BitBox, order::Msb0, slice::BitSlice, vec::BitVec};
use futures::{FutureExt, future::BoxFuture};
use tracing::debug_span;

use crate::{spawn_utils::BlockingSpawner, storage::filesystem::OurFileExt};

pub trait BitV: Send + Sync {
    fn as_slice(&self) -> &BitSlice<u8, Msb0>;
    fn as_slice_mut(&mut self) -> &mut BitSlice<u8, Msb0>;
    fn into_dyn(self) -> Box<dyn BitV>;
    fn as_bytes(&self) -> &[u8];
    fn flush(&mut self, flush_async: bool) -> anyhow::Result<()>;

    /// Resolves once every write queued by [`BitV::flush`] before this call has reached
    /// storage. Queues no write of its own. Implementations that write synchronously, or not
    /// at all, resolve at once.
    fn wait_flushed(&self) -> BoxFuture<'static, anyhow::Result<()>> {
        futures::future::ok(()).boxed()
    }
}

pub type BoxBitV = Box<dyn BitV>;

enum DiskFlushRequest {
    /// Write this snapshot of the bitfield.
    Write(BitBox<u8, Msb0>),
    /// Acknowledge once every snapshot queued before this request has been written.
    Barrier(tokio::sync::oneshot::Sender<()>),
}

pub struct DiskBackedBitV {
    bv: BitBox<u8, Msb0>,
    flush_tx: tokio::sync::mpsc::UnboundedSender<DiskFlushRequest>,
}

impl Drop for DiskBackedBitV {
    fn drop(&mut self) {
        if self
            .flush_tx
            .send(DiskFlushRequest::Write(self.bv.clone()))
            .is_err()
        {
            tracing::warn!("error flushing bitv on drop: flusher task is dead")
        }
    }
}

/// Merges a queued request into the batch the flusher is about to handle. Only the latest
/// snapshot is worth writing: it supersedes the earlier ones.
fn absorb(
    req: DiskFlushRequest,
    snapshot: &mut Option<BitBox<u8, Msb0>>,
    barriers: &mut Vec<tokio::sync::oneshot::Sender<()>>,
) {
    match req {
        DiskFlushRequest::Write(s) => *snapshot = Some(s),
        DiskFlushRequest::Barrier(tx) => barriers.push(tx),
    }
}

// NOTE on mmap. rqbit used it for a while, but it has issues on slow disks.
// We want writes to bitv to be instant in RAM. However when disk is slow, occasionally
// the writes stall which blocks the executor.
// Thus this separate "thread" of flushing was implemented.
impl DiskBackedBitV {
    pub async fn new(filename: PathBuf, spawner: BlockingSpawner) -> anyhow::Result<Self> {
        let buf = tokio::fs::read(&filename)
            .await
            .with_context(|| format!("error reading {filename:?}"))?;
        let bv = BitVec::from_vec(buf).into_boxed_bitslice();

        // blocking file to avoid double-buffering and double-memcpy
        let file = spawner
            .block_in_place_with_semaphore(|| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(false)
                    .open(&filename)
            })
            .await
            .with_context(|| format!("error opening {filename:?}"))?;

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DiskFlushRequest>();
        librqbit_core::spawn_utils::spawn(
            debug_span!("diskbitv-flusher", ?filename),
            format!("DiskBackedBitV::flusher {filename:?}"),
            async move {
                loop {
                    let Some(first) = rx.recv().await else {
                        break;
                    };
                    let mut snapshot = None;
                    let mut barriers = Vec::new();
                    absorb(first, &mut snapshot, &mut barriers);
                    while let Ok(r) = rx.try_recv() {
                        absorb(r, &mut snapshot, &mut barriers);
                    }

                    if let Some(snapshot) = snapshot {
                        if let Err(e) = spawner
                            .block_in_place_with_semaphore(|| {
                                file.pwrite_all(0, snapshot.as_raw_slice())
                            })
                            .await
                        {
                            tracing::error!(?filename, "error writing to bitv: {e:#}");
                            if let Err(e) = tokio::fs::remove_file(&filename).await {
                                tracing::error!(?filename, "error removing bitv: {e:#}");
                            }
                            // Dropping the barriers tells their waiters that the write failed.
                            break;
                        }

                        if let Err(e) = spawner
                            .block_in_place_with_semaphore(|| file.sync_all())
                            .await
                        {
                            tracing::error!(?filename, "error fsyncing bitv: {e:#}");
                        }
                    }

                    for barrier in barriers {
                        if barrier.send(()).is_err() {
                            tracing::debug!(?filename, "bitv flush waiter went away");
                        }
                    }
                }

                Ok::<_, anyhow::Error>(())
            },
        );
        Ok(Self { bv, flush_tx: tx })
    }
}

#[async_trait::async_trait]
impl BitV for BitBox<u8, Msb0> {
    fn as_slice(&self) -> &BitSlice<u8, Msb0> {
        self.as_bitslice()
    }

    fn as_slice_mut(&mut self) -> &mut BitSlice<u8, Msb0> {
        self.as_mut_bitslice()
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_raw_slice()
    }

    fn flush(&mut self, _flush_async: bool) -> anyhow::Result<()> {
        Ok(())
    }

    fn into_dyn(self) -> Box<dyn BitV> {
        Box::new(self)
    }
}

impl BitV for DiskBackedBitV {
    fn as_slice(&self) -> &BitSlice<u8, Msb0> {
        self.bv.as_bitslice()
    }

    fn as_slice_mut(&mut self) -> &mut BitSlice<u8, Msb0> {
        self.bv.as_mut_bitslice()
    }

    fn as_bytes(&self) -> &[u8] {
        self.bv.as_raw_slice()
    }

    fn flush(&mut self, _flush_async: bool) -> anyhow::Result<()> {
        self.flush_tx
            .send(DiskFlushRequest::Write(self.bv.clone()))
            .context("flusher task is dead")
    }

    fn wait_flushed(&self) -> BoxFuture<'static, anyhow::Result<()>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let queued = self.flush_tx.send(DiskFlushRequest::Barrier(tx)).is_ok();
        async move {
            anyhow::ensure!(queued, "flusher task is dead");
            rx.await
                .context("flusher task stopped before writing the bitfield")
        }
        .boxed()
    }

    fn into_dyn(self) -> Box<dyn BitV> {
        Box::new(self)
    }
}

impl BitV for Box<dyn BitV> {
    fn as_slice(&self) -> &BitSlice<u8, Msb0> {
        (**self).as_slice()
    }

    fn as_slice_mut(&mut self) -> &mut BitSlice<u8, Msb0> {
        (**self).as_slice_mut()
    }

    fn as_bytes(&self) -> &[u8] {
        (**self).as_bytes()
    }

    fn flush(&mut self, flush_async: bool) -> anyhow::Result<()> {
        (**self).flush(flush_async)
    }

    fn wait_flushed(&self) -> BoxFuture<'static, anyhow::Result<()>> {
        (**self).wait_flushed()
    }

    fn into_dyn(self) -> Box<dyn BitV> {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    async fn disk_bitv(
        dir: &tempfile::TempDir,
        bytes: &[u8],
        spawner: BlockingSpawner,
    ) -> anyhow::Result<(PathBuf, DiskBackedBitV)> {
        let path = dir.path().join("test.bitv");
        tokio::fs::write(&path, bytes).await?;
        let bv = DiskBackedBitV::new(path.clone(), spawner).await?;
        Ok((path, bv))
    }

    // The acknowledgement comes once the queued snapshots are written, not when they are taken
    // off the queue. Several flushes and waiters queued meanwhile are served by one write of
    // the latest snapshot.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_wait_flushed_resolves_after_the_queued_writes() -> anyhow::Result<()> {
        let dir = tempfile::TempDir::with_prefix("rqbit_bitv")?;
        let spawner = BlockingSpawner::new(1);
        let (path, mut bv) = disk_bitv(&dir, &[0, 0], spawner.clone()).await?;

        // Holding the only blocking permit stalls the flusher, like a slow disk.
        let disk = spawner.semaphore().acquire_owned().await?;
        bv.as_slice_mut().set(1, true);
        bv.flush(true)?;
        let mut first = bv.wait_flushed();
        bv.as_slice_mut().set(9, true);
        bv.flush(true)?;
        let second = bv.wait_flushed();

        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut first)
                .await
                .is_err(),
            "acknowledged before the write"
        );
        assert_eq!(tokio::fs::read(&path).await?, [0, 0]);

        drop(disk);
        first.await?;
        second.await?;
        assert_eq!(tokio::fs::read(&path).await?, [0b0100_0000, 0b0100_0000]);
        Ok(())
    }

    // Waiting writes nothing: changes that were never flushed stay off the disk.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_wait_flushed_does_not_write_by_itself() -> anyhow::Result<()> {
        let dir = tempfile::TempDir::with_prefix("rqbit_bitv")?;
        let (path, mut bv) = disk_bitv(&dir, &[0, 0], BlockingSpawner::new(1)).await?;

        bv.as_slice_mut().set(0, true);
        bv.wait_flushed().await?;
        assert_eq!(tokio::fs::read(&path).await?, [0, 0]);

        bv.flush(true)?;
        bv.wait_flushed().await?;
        assert_eq!(tokio::fs::read(&path).await?, [0b1000_0000, 0]);
        Ok(())
    }

    // In-memory bitfields have nothing to wait for.
    #[tokio::test]
    async fn test_wait_flushed_in_memory() -> anyhow::Result<()> {
        let bv: BoxBitV = BitVec::<u8, Msb0>::repeat(false, 16)
            .into_boxed_bitslice()
            .into_dyn();
        bv.wait_flushed().await
    }
}
