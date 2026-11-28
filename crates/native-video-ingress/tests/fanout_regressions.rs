use ctdozlite_native_video_ingress::fanout::VideoFanout;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[test]
fn overflow_waits_for_idr_without_blocking_other_legs() {
    let enabled = Arc::new(AtomicBool::new(true));
    let mut fanout = VideoFanout::default();
    let slow = fanout.subscribe(&enabled);
    let fast = fanout.subscribe(&enabled);
    assert!(fanout.take_keyframe_request());
    fanout.publish(vec![1], true);
    assert_eq!(fanout.pop(fast), Some(vec![1]));
    for n in 2..=5 {
        fanout.publish(vec![n], false);
        assert_eq!(fanout.pop(fast), Some(vec![n]));
    }
    assert_eq!(fanout.pop(slow), None);
    assert!(fanout.take_keyframe_request());
    fanout.publish(vec![6], true);
    assert_eq!(fanout.pop(slow), Some(vec![6]));
}

#[test]
fn new_or_reenabled_leg_waits_for_fresh_idr() {
    let enabled = Arc::new(AtomicBool::new(true));
    let mut fanout = VideoFanout::default();
    let leg = fanout.subscribe(&enabled);
    fanout.publish(vec![1], true);
    enabled.store(false, Ordering::Release);
    fanout.publish(vec![2], false);
    enabled.store(true, Ordering::Release);
    fanout.publish(vec![3], false);
    assert_eq!(fanout.pop(leg), None);
    fanout.publish(vec![4], true);
    assert_eq!(fanout.pop(leg), Some(vec![4]));
    fanout.unsubscribe(leg);
    assert_eq!(fanout.pop(leg), None);
}

#[test]
fn disabling_all_invalidates_queues_and_updates_permissions() {
    let enabled = Arc::new(AtomicBool::new(true));
    let mut fanout = VideoFanout::default();
    let leg = fanout.subscribe(&enabled);
    fanout.publish(vec![1], true);
    assert!(fanout.has_enabled_legs());
    fanout.disable_all();
    assert!(!enabled.load(Ordering::Acquire));
    assert!(!fanout.has_enabled_legs());
    assert_eq!(fanout.pop(leg), None);
    assert!(fanout.take_keyframe_request());
}
