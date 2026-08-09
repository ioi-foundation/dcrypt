//! Error registry for compatibility with deferred error handling APIs.

#[cfg(feature = "std")]
use core::any::Any;
#[cfg(not(feature = "std"))]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "std")]
use std::boxed::Box;
#[cfg(feature = "std")]
use std::sync::{Mutex, MutexGuard};

/// Global error registry for recording the most recent deferred error.
///
/// The registry is retained for API compatibility. Prefer returning errors to
/// the caller directly: a process-global "last error" can be overwritten by an
/// unrelated operation at any time.
pub static ERROR_REGISTRY: ErrorRegistry = ErrorRegistry::new();

/// A synchronized, type-checked registry for a single error value.
///
/// Under `std`, stored errors are owned by a `Mutex` and retrieved using a
/// checked [`core::any::Any`] downcast. A request for a different type returns
/// `None`. Under `no_std`, where this crate has no synchronization primitive
/// capable of owning an arbitrary allocation, the registry records only
/// whether an error occurred.
pub struct ErrorRegistry {
    #[cfg(feature = "std")]
    state: Mutex<RegistryState>,
    #[cfg(not(feature = "std"))]
    has_error: AtomicBool,
}

#[cfg(feature = "std")]
struct RegistryState {
    error: Option<Box<dyn Any + Send>>,
    generation: u64,
}

impl ErrorRegistry {
    /// Create a new, empty error registry.
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "std")]
            state: Mutex::new(RegistryState {
                error: None,
                generation: 0,
            }),
            #[cfg(not(feature = "std"))]
            has_error: AtomicBool::new(false),
        }
    }

    /// Store an error in the registry, replacing the previous value.
    ///
    /// Errors must be owned and safe to move between threads because the
    /// registry is process-global. The replaced value is dropped after the
    /// registry lock is released so user-defined destructors cannot deadlock
    /// the registry by re-entering it.
    pub fn store<E>(&self, error: E)
    where
        E: Send + 'static,
    {
        #[cfg(feature = "std")]
        {
            let old = {
                let mut state = self.lock();
                state.generation = state.generation.wrapping_add(1);
                state.error.replace(Box::new(error))
            };
            drop(old);
        }

        #[cfg(not(feature = "std"))]
        {
            drop(error);
            self.has_error.store(true, Ordering::Release);
        }
    }

    /// Clear and drop the stored error, if any.
    pub fn clear(&self) {
        #[cfg(feature = "std")]
        {
            let old = {
                let mut state = self.lock();
                state.generation = state.generation.wrapping_add(1);
                state.error.take()
            };
            drop(old);
        }

        #[cfg(not(feature = "std"))]
        self.has_error.store(false, Ordering::Release);
    }

    /// Check whether an error is currently present.
    pub fn has_error(&self) -> bool {
        #[cfg(feature = "std")]
        {
            self.lock().error.is_some()
        }

        #[cfg(not(feature = "std"))]
        {
            self.has_error.load(Ordering::Acquire)
        }
    }

    /// Clone the stored error if its concrete type is exactly `E`.
    ///
    /// A type mismatch returns `None`; callers can never reinterpret the
    /// allocation as another type.
    #[cfg(feature = "std")]
    pub fn get_error<E>(&self) -> Option<E>
    where
        E: Clone + Send + 'static,
    {
        // Temporarily remove the allocation so user-defined `Clone` code runs
        // without the registry mutex held. If another operation mutates the
        // registry while cloning, that newer operation wins and the old value
        // is dropped instead of being restored.
        let (stored, generation) = {
            let mut state = self.lock();
            let stored = state.error.take()?;
            (stored, state.generation)
        };

        let cloned = stored.downcast_ref::<E>().cloned();

        let displaced = {
            let mut state = self.lock();
            if state.generation == generation && state.error.is_none() {
                state.error = Some(stored);
                None
            } else {
                Some(stored)
            }
        };
        drop(displaced);

        cloned
    }

    #[cfg(feature = "std")]
    fn lock(&self) -> MutexGuard<'_, RegistryState> {
        // A panic in a user-provided Clone implementation can poison the
        // mutex. Poisoning does not make the owned value unsafe, so recover the
        // guard and keep the registry usable.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for ErrorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ErrorRegistry {
    fn drop(&mut self) {
        #[cfg(feature = "std")]
        {
            let state = self
                .state
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            drop(state.error.take());
        }

        #[cfg(not(feature = "std"))]
        self.has_error.store(false, Ordering::Release);
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::ErrorRegistry;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn retrieves_only_the_stored_concrete_type() {
        let registry = ErrorRegistry::new();
        registry.store([0xA5_u8; 4096]);

        assert_eq!(registry.get_error::<u8>(), None);
        assert_eq!(registry.get_error::<String>(), None);
        assert_eq!(registry.get_error::<[u8; 4096]>(), Some([0xA5; 4096]));
    }

    #[test]
    fn replacing_and_clearing_drop_each_value_exactly_once() {
        #[derive(Clone)]
        struct DropTracker(Arc<AtomicUsize>);

        impl Drop for DropTracker {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let registry = ErrorRegistry::new();

        registry.store(DropTracker(Arc::clone(&drops)));
        registry.store(DropTracker(Arc::clone(&drops)));
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        registry.clear();
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert!(!registry.has_error());
    }

    #[test]
    fn concurrent_store_get_and_clear_keep_values_owned() {
        #[derive(Clone, Debug)]
        struct Payload {
            value: usize,
            complement: usize,
            padding: [usize; 16],
        }

        #[derive(Clone, Debug)]
        struct SmallPayload {
            value: usize,
            complement: usize,
        }

        let registry = Arc::new(ErrorRegistry::new());
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        let iterations = if cfg!(miri) { 16 } else { 2_000 };

        for worker in 0..8 {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                for sequence in 0..iterations {
                    let value = (worker << 24) | sequence;
                    if sequence % 2 == 0 {
                        registry.store(Payload {
                            value,
                            complement: !value,
                            padding: [value; 16],
                        });
                    } else {
                        registry.store(SmallPayload {
                            value,
                            complement: !value,
                        });
                    }

                    if let Some(payload) = registry.get_error::<Payload>() {
                        assert_eq!(payload.complement, !payload.value);
                        assert!(payload.padding.iter().all(|item| *item == payload.value));
                    }

                    if let Some(payload) = registry.get_error::<SmallPayload>() {
                        assert_eq!(payload.complement, !payload.value);
                    }

                    if sequence % 7 == 0 {
                        registry.clear();
                    }
                }
            }));
        }

        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn user_clone_can_reenter_registry_without_deadlock() {
        struct ReentrantClone(Arc<ErrorRegistry>);

        impl Clone for ReentrantClone {
            fn clone(&self) -> Self {
                // The value is temporarily out of the registry while Clone is
                // invoked, so this reentrant call neither deadlocks nor sees a
                // borrowed allocation that another thread could free.
                assert!(!self.0.has_error());
                Self(Arc::clone(&self.0))
            }
        }

        let registry = Arc::new(ErrorRegistry::new());
        registry.store(ReentrantClone(Arc::clone(&registry)));

        assert!(registry.get_error::<ReentrantClone>().is_some());
        assert!(registry.has_error());
        // Break the deliberate Arc cycle created for this reentrancy test so
        // leak-checking interpreters can verify the registry itself cleanly.
        registry.clear();
        assert!(!registry.has_error());
    }
}

#[cfg(all(test, not(feature = "std")))]
mod no_std_tests {
    use super::ErrorRegistry;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);

    struct DropTracker;

    impl Drop for DropTracker {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn presence_only_registry_drops_values_and_tracks_state() {
        DROPS.store(0, Ordering::SeqCst);
        let registry = ErrorRegistry::new();

        registry.store(DropTracker);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        assert!(registry.has_error());

        registry.clear();
        assert!(!registry.has_error());
    }
}
