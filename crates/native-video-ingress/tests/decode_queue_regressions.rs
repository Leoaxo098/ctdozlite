#![allow(dead_code)]
include!("../src/decode_queue.rs");

mod tests {
    use super::*;

    /// Check that overflow makes the decoder consume a reset with the newest
    /// access unit and leaves no older references queued.
    #[test]
    fn overflow_discards_reference_backlog_and_retains_fresh_unit() {
        let queue = DecodeQueue::default();
        queue.synced.store(true, Ordering::Release);
        for value in 0..8 {
            assert!(queue.push(vec![value]));
        }
        assert!(!queue.push(vec![9]));
        assert!(!queue.synced.load(Ordering::Acquire));
        assert_eq!(queue.pop(Duration::ZERO), (true, Some(vec![9])));
        assert_eq!(queue.pop(Duration::ZERO), (false, None));
    }

    #[test]
    fn rejects_oversized_unit_and_invalidates_old_references() {
        let queue = DecodeQueue::default();
        queue.push(vec![1]);
        assert!(!queue.push(vec![0; 1024 * 1024 + 1]));
        assert_eq!(queue.pop(Duration::ZERO), (true, None));
        assert!(queue.push(vec![2]));
        assert_eq!(queue.pop(Duration::ZERO), (false, Some(vec![2])));
    }

    #[test]
    fn reset_is_consumed_once_and_wakes_waiter() {
        let queue = Arc::new(DecodeQueue::default());
        let waiting = queue.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            tx.send(waiting.pop(Duration::from_secs(3))).unwrap();
        });
        queue.synced.store(true, Ordering::Release);
        queue.reset();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(500)).unwrap(),
            (true, None)
        );
        assert!(!queue.synced.load(Ordering::Acquire));
        assert_eq!(queue.pop(Duration::ZERO), (false, None));
        worker.join().unwrap();
    }

    #[test]
    fn reset_during_decode_prevents_restoring_stale_synchronization() {
        let queue = DecodeQueue::default();
        queue.push(vec![1]);
        assert_eq!(queue.pop(Duration::ZERO), (false, Some(vec![1])));
        queue.reset();
        assert!(!queue.finish_frame());
        assert!(!queue.synced.load(Ordering::Acquire));
        assert_eq!(queue.pop(Duration::ZERO), (true, None));
        assert!(queue.finish_frame());
        assert!(queue.synced.load(Ordering::Acquire));
    }
}
