//! The fast-resume bitfield on disk keeps up with what was downloaded when a torrent is paused
//! or the session is stopped, even if far less than the periodic flush threshold was completed.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use parking_lot::Mutex;
use tokio::time::timeout;

use super::{
    fake_peer::{
        ClientOpts, FakePeer, Fixture, PIECE_LEN, Recv, SeederOpts, Wire, peer_id, run,
        start_client, start_seeder,
    },
    test_util::wait_until,
};

/// The first two of the four pieces.
const SERVED_FIRST: [u32; 2] = [0, 1];
const SERVED_FIRST_BITS: u8 = 0b1100_0000;

type RequestLog = Arc<Mutex<Vec<(u32, u32, u32)>>>;

/// The fast-resume file of the client's torrent.
fn read_bitv(client: &Fixture) -> anyhow::Result<Vec<u8>> {
    let path = client
        ._dir
        .path()
        .join("session")
        .join(format!("{:?}.bitv", client.info_hash));
    std::fs::read(&path).with_context(|| format!("error reading {path:?}"))
}

async fn wait_for_bitv(client: &Fixture, expected: &[u8]) -> anyhow::Result<()> {
    wait_until(
        || {
            let bits = read_bitv(client)?;
            anyhow::ensure!(bits == expected, "bitfield on disk: {bits:?}");
            Ok(())
        },
        Duration::from_secs(20),
    )
    .await
}

/// Connects to `client` as a peer that has every piece, and uploads the blocks of `served`
/// only: requests for other pieces go unanswered. Returns the log of every request received.
async fn fake_seeder(
    client: &Fixture,
    seed: &Fixture,
    served: &[u32],
) -> anyhow::Result<RequestLog> {
    let mut peer =
        FakePeer::connect(client.addr(), client.info_hash, &peer_id(b"-FK0001-")).await?;
    peer.bitfield(&[0b1111_0000]).await?;
    peer.unchoke().await?;

    let log = RequestLog::default();
    let served = served.to_vec();
    let content = seed.content.clone();
    tokio::spawn({
        let log = log.clone();
        async move {
            loop {
                match peer.recv(Duration::from_secs(3600)).await {
                    Recv::Msg(Wire::Request(piece, begin, len)) => {
                        log.lock().push((piece, begin, len));
                        if !served.contains(&piece) {
                            continue;
                        }
                        let start = (piece * PIECE_LEN + begin) as usize;
                        let block = content
                            .get(start..start + len as usize)
                            .context("request out of range")?;
                        peer.piece(piece, begin, block).await?;
                    }
                    Recv::Msg(_) => {}
                    Recv::Timeout | Recv::Closed => return Ok::<_, anyhow::Error>(()),
                }
            }
        }
    });
    Ok(log)
}

/// A client with fast-resume persistence that downloaded the first two pieces of the seeder's
/// torrent, and waits for the rest.
async fn client_with_two_pieces(seed: &Fixture) -> anyhow::Result<Fixture> {
    let client = start_client(
        seed,
        ClientOpts {
            listen: true,
            persistence: true,
            ..Default::default()
        },
    )
    .await?;
    fake_seeder(&client, seed, &SERVED_FIRST).await?;
    let two_pieces = 2 * u64::from(PIECE_LEN);
    wait_until(
        || {
            let progress = client.handle.stats().progress_bytes;
            anyhow::ensure!(progress == two_pieces, "progress {progress}");
            Ok(())
        },
        Duration::from_secs(20),
    )
    .await?;
    // Far below the periodic flush threshold, and the torrent is not finished: nothing was
    // written yet. Otherwise the tests below would prove nothing.
    assert_eq!(read_bitv(&client)?, [0]);
    Ok(client)
}

// Pausing writes the pieces completed since the last flush to the fast-resume file.
#[tokio::test(flavor = "multi_thread")]
async fn test_pause_flushes_bitfield() -> anyhow::Result<()> {
    run(async {
        let seed = start_seeder(SeederOpts::default()).await?;
        let client = client_with_two_pieces(&seed).await?;

        client.session.pause(&client.handle).await?;
        wait_for_bitv(&client, &[SERVED_FIRST_BITS]).await
    })
    .await
}

// Session::stop does not return before the bitfield is on disk, even when the disk is slow.
#[tokio::test(flavor = "multi_thread")]
async fn test_stop_waits_for_bitfield_write() -> anyhow::Result<()> {
    run(async {
        let seed = start_seeder(SeederOpts::default()).await?;
        let client = client_with_two_pieces(&seed).await?;

        // Taking every blocking permit of the session stalls the bitfield writer, like a slow
        // disk would.
        let semaphore = client.handle.shared().spawner.semaphore();
        let permits = u32::try_from(semaphore.available_permits())?;
        let disk = semaphore.acquire_many_owned(permits).await?;

        let session = client.session.clone();
        let mut stop = tokio::spawn(async move { session.stop().await });
        let returned_early = timeout(Duration::from_secs(3), &mut stop).await.is_ok();
        drop(disk);
        assert!(
            !returned_early,
            "stop returned while the bitfield could not be written"
        );
        stop.await?;

        assert_eq!(read_bitv(&client)?, [SERVED_FIRST_BITS]);
        Ok(())
    })
    .await
}

// After a pause and a restart, the pieces downloaded before are not asked for again.
#[tokio::test(flavor = "multi_thread")]
async fn test_restart_after_pause_keeps_downloaded_pieces() -> anyhow::Result<()> {
    run(async {
        let seed = start_seeder(SeederOpts::default()).await?;
        let client = client_with_two_pieces(&seed).await?;
        client.session.pause(&client.handle).await?;
        wait_for_bitv(&client, &[SERVED_FIRST_BITS]).await?;
        client.session.stop().await;
        let Fixture { _dir: dir, .. } = client;

        // The new session restores the torrent, paused, from the persistence in the folder;
        // adding it again returns that one.
        let client = start_client(
            &seed,
            ClientOpts {
                listen: true,
                persistence: true,
                dir: Some(dir),
                ..Default::default()
            },
        )
        .await?;
        assert!(client.handle.is_paused(), "the torrent was not restored");
        assert_eq!(
            client.handle.stats().progress_bytes,
            2 * u64::from(PIECE_LEN)
        );

        client.session.unpause(&client.handle).await?;
        let log = fake_seeder(&client, &seed, &[0, 1, 2, 3]).await?;
        timeout(
            Duration::from_secs(20),
            client.handle.wait_until_completed(),
        )
        .await
        .context("the torrent did not complete")??;

        let requests = log.lock().clone();
        assert!(!requests.is_empty());
        assert!(
            requests
                .iter()
                .all(|(piece, ..)| !SERVED_FIRST.contains(piece)),
            "downloaded again: {requests:?}"
        );
        Ok(())
    })
    .await
}
