//! Schedule model for the ErrorRegistry get/replace/clear ownership protocol.
//!
//! `ErrorRegistry` itself uses a `const` process-global `std::sync::Mutex`, so
//! substituting Loom's non-const mutex in the public type would change its API.
//! This model isolates the same generation-and-restore state machine while the
//! unit tests in `error::registry` exercise the real implementation with threads.

use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

struct TrackedValue {
    id: usize,
    drops: Arc<AtomicUsize>,
}

impl Drop for TrackedValue {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct State {
    value: Option<TrackedValue>,
    generation: usize,
}

#[derive(Default)]
struct RegistryModel {
    state: Mutex<State>,
}

impl RegistryModel {
    fn store(&self, value: TrackedValue) {
        let replaced = {
            let mut state = self.state.lock().unwrap();
            state.generation = state.generation.wrapping_add(1);
            state.value.replace(value)
        };
        drop(replaced);
    }

    fn clear(&self) {
        let removed = {
            let mut state = self.state.lock().unwrap();
            state.generation = state.generation.wrapping_add(1);
            state.value.take()
        };
        drop(removed);
    }

    fn take_for_clone(&self) -> Option<(TrackedValue, usize)> {
        let mut state = self.state.lock().unwrap();
        let value = state.value.take()?;
        Some((value, state.generation))
    }

    fn restore_if_unchanged(&self, value: TrackedValue, generation: usize) {
        let displaced = {
            let mut state = self.state.lock().unwrap();
            if state.generation == generation && state.value.is_none() {
                state.value = Some(value);
                None
            } else {
                Some(value)
            }
        };
        drop(displaced);
    }

    fn current_id(&self) -> Option<usize> {
        self.state
            .lock()
            .unwrap()
            .value
            .as_ref()
            .map(|value| value.id)
    }
}

fn tracked(id: usize, drops: &Arc<AtomicUsize>) -> TrackedValue {
    TrackedValue {
        id,
        drops: Arc::clone(drops),
    }
}

#[test]
fn replacement_during_clone_window_wins_without_double_drop() {
    loom::model(|| {
        let drops = Arc::new(AtomicUsize::new(0));
        let registry = Arc::new(RegistryModel::default());
        registry.store(tracked(1, &drops));

        let taken = Arc::new(AtomicBool::new(false));
        let replaced = Arc::new(AtomicBool::new(false));

        let getter = {
            let registry = Arc::clone(&registry);
            let taken = Arc::clone(&taken);
            let replaced = Arc::clone(&replaced);
            thread::spawn(move || {
                let (value, generation) = registry.take_for_clone().unwrap();
                let observed = value.id;
                taken.store(true, Ordering::Release);
                while !replaced.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                registry.restore_if_unchanged(value, generation);
                observed
            })
        };

        let writer = {
            let registry = Arc::clone(&registry);
            let drops = Arc::clone(&drops);
            let taken = Arc::clone(&taken);
            let replaced = Arc::clone(&replaced);
            thread::spawn(move || {
                while !taken.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                registry.store(tracked(2, &drops));
                replaced.store(true, Ordering::Release);
            })
        };

        assert_eq!(getter.join().unwrap(), 1);
        writer.join().unwrap();
        assert_eq!(registry.current_id(), Some(2));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(registry);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn clear_during_clone_window_prevents_stale_restoration() {
    loom::model(|| {
        let drops = Arc::new(AtomicUsize::new(0));
        let registry = Arc::new(RegistryModel::default());
        registry.store(tracked(1, &drops));

        let taken = Arc::new(AtomicBool::new(false));
        let cleared = Arc::new(AtomicBool::new(false));

        let getter = {
            let registry = Arc::clone(&registry);
            let taken = Arc::clone(&taken);
            let cleared = Arc::clone(&cleared);
            thread::spawn(move || {
                let (value, generation) = registry.take_for_clone().unwrap();
                taken.store(true, Ordering::Release);
                while !cleared.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                registry.restore_if_unchanged(value, generation);
            })
        };

        let clearer = {
            let registry = Arc::clone(&registry);
            let taken = Arc::clone(&taken);
            let cleared = Arc::clone(&cleared);
            thread::spawn(move || {
                while !taken.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                registry.clear();
                cleared.store(true, Ordering::Release);
            })
        };

        getter.join().unwrap();
        clearer.join().unwrap();
        assert_eq!(registry.current_id(), None);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(registry);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    });
}
