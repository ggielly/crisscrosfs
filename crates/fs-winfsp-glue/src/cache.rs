//! LRU (Least Recently Used) Cache implementation.
//!
//! Ported from kernel-mode implementation, adapted for user-mode std.

use std::{collections::VecDeque, hash::Hash};

/// A simple LRU (Least Recently Used) cache.
///
/// This cache maintains a fixed maximum size and evicts the least recently
/// used item when the capacity is exceeded.
pub struct LruCache<K, V> {
    /// Maximum number of items the cache can hold
    capacity: usize,
    /// Storage for cache entries as (key, value) pairs
    entries: VecDeque<(K, V)>,
}

impl<K, V> LruCache<K, V>
where
    K: Eq + Hash + Clone,
{
    /// Creates a new LRU cache with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: VecDeque::with_capacity(capacity.min(100)),
        }
    }

    /// Gets a reference to the value associated with the key, if it exists.
    /// Moves the accessed item to the front (most recently used).
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if let Some(pos) = self.entries.iter().position(|(k, _)| k == key) {
            // Move the accessed element to the front
            let entry = self.entries.remove(pos).unwrap();
            self.entries.push_front(entry);
            Some(&self.entries[0].1)
        } else {
            None
        }
    }

    /// Gets a mutable reference to the value associated with the key, if it
    /// exists. Moves the accessed item to the front (most recently used).
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        if let Some(pos) = self.entries.iter().position(|(k, _)| k == key) {
            // Move the accessed element to the front
            let entry = self.entries.remove(pos).unwrap();
            self.entries.push_front(entry);
            Some(&mut self.entries[0].1)
        } else {
            None
        }
    }

    /// Inserts a key-value pair into the cache.
    /// If the cache is at capacity, the least recently used item is evicted.
    pub fn put(&mut self, key: K, value: V) {
        // Check if key already exists
        if let Some(pos) = self.entries.iter().position(|(k, _)| k == &key) {
            // Remove existing entry
            self.entries.remove(pos);
        } else if self.entries.len() >= self.capacity {
            // Remove least recently used item (the last one)
            self.entries.pop_back();
        }

        // Insert new entry at the front
        self.entries.push_front((key, value));
    }

    /// Removes an entry from the cache by key.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Some(pos) = self.entries.iter().position(|(k, _)| k == key) {
            let (_, value) = self.entries.remove(pos).unwrap();
            Some(value)
        } else {
            None
        }
    }

    /// Returns the number of items currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clears all entries from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the capacity of the cache.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Resizes the cache, potentially removing entries if new capacity is
    /// smaller.
    pub fn resize(&mut self, new_capacity: usize) {
        self.capacity = new_capacity;
        while self.entries.len() > self.capacity {
            self.entries.pop_back();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_and_get() {
        let mut cache = LruCache::new(2);
        cache.put(1, "one");
        cache.put(2, "two");

        assert_eq!(cache.get(&1), Some(&"one"));
        assert_eq!(cache.get(&2), Some(&"two"));
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache = LruCache::new(2);
        cache.put(1, "one");
        cache.put(2, "two");
        // Access 1 to make it recently used
        assert_eq!(cache.get(&1), Some(&"one"));
        // Add 3, which should evict 2 (least recently used)
        cache.put(3, "three");

        assert_eq!(cache.get(&1), Some(&"one")); // Still there
        assert_eq!(cache.get(&2), None); // Evicted
        assert_eq!(cache.get(&3), Some(&"three")); // Newly added
    }

    #[test]
    fn test_update_existing() {
        let mut cache = LruCache::new(2);
        cache.put(1, "one");
        cache.put(1, "ONE");

        assert_eq!(cache.get(&1), Some(&"ONE"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut cache = LruCache::new(2);
        cache.put(1, "one");
        cache.put(2, "two");
        cache.clear();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }
}
