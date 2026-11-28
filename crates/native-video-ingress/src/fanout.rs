//! Bounded per-leg fanout for an encoded video stream.
use std::collections::{BTreeMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Weak,
};

const QUEUE_CAPACITY: usize = 4;

#[derive(Default)]
struct Slot {
    frames: VecDeque<Vec<u8>>,
    waiting_idr: bool,
    enabled: Weak<AtomicBool>,
}

/// Distributes access units independently to the active call legs.
#[derive(Default)]
pub struct VideoFanout {
    next_id: u64,
    slots: BTreeMap<u64, Slot>,
    need_idr: bool,
}

impl VideoFanout {
    /// Registers a leg and requires a fresh keyframe before delivery.
    pub fn subscribe(&mut self, enabled: &Arc<AtomicBool>) -> u64 {
        self.next_id += 1;
        self.slots.insert(
            self.next_id,
            Slot {
                enabled: Arc::downgrade(enabled),
                waiting_idr: true,
                ..Default::default()
            },
        );
        self.need_idr = true;
        self.next_id
    }

    /// Removes a departed leg.
    pub fn unsubscribe(&mut self, id: u64) {
        self.slots.remove(&id);
    }

    /// Invalidates queued references for every leg and requests a keyframe.
    pub fn invalidate(&mut self) {
        self.need_idr = true;
        for slot in self.slots.values_mut() {
            slot.frames.clear();
            slot.waiting_idr = true;
        }
    }

    /// Returns and clears the pending keyframe request.
    pub fn take_keyframe_request(&mut self) -> bool {
        std::mem::take(&mut self.need_idr)
    }

    /// Requests a fresh keyframe for the next published access unit.
    pub fn request_keyframe(&mut self) {
        self.need_idr = true;
    }

    /// Whether at least one registered leg currently requests video.
    pub fn has_enabled_legs(&self) -> bool {
        self.slots.values().any(|slot| {
            slot.enabled
                .upgrade()
                .is_some_and(|enabled| enabled.load(Ordering::Acquire))
        })
    }

    /// Disable all surviving legs and invalidate their queued references.
    pub fn disable_all(&mut self) {
        self.invalidate();
        for slot in self.slots.values() {
            if let Some(enabled) = slot.enabled.upgrade() {
                enabled.store(false, Ordering::Release);
            }
        }
    }

    /// Delivers units in order, independently recovering disabled or overflowing legs.
    pub fn publish(&mut self, au: Vec<u8>, idr: bool) {
        for slot in self.slots.values_mut() {
            if !slot
                .enabled
                .upgrade()
                .is_some_and(|enabled| enabled.load(Ordering::Acquire))
            {
                slot.frames.clear();
                slot.waiting_idr = true;
                continue;
            }
            if slot.frames.len() >= QUEUE_CAPACITY {
                slot.frames.clear();
                slot.waiting_idr = true;
                self.need_idr = true;
            }
            if slot.waiting_idr && !idr {
                continue;
            }
            slot.waiting_idr = false;
            slot.frames.push_back(au.clone());
        }
    }

    /// Reads one queued unit for a leg without blocking.
    pub fn pop(&mut self, id: u64) -> Option<Vec<u8>> {
        self.slots.get_mut(&id)?.frames.pop_front()
    }
}
