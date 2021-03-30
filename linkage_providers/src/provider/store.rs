//! Contains an implementation for a store.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use crate::error::ProviderResult;

/// A value that is stored inside a `Store`. Can contain either another store or a value that
/// vector of `u8`. The data holds the serialized content of the actual value.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum StoreContent {
    Value(Vec<u8>),
    NestedStore(Store),
}

/// A HashMap used to store the data inside a `Store`.
type StoreHashMap = HashMap<String, StoreContent>;

/// A `Store` is responsible for saving information for providers, like authentication information
/// or session tokens. It stores the data inside a `StoreHashMap` that contains the serialized
/// values.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Store {
    identifier: String,
    data: StoreHashMap,
}

impl Store {
    /// Returns a new instance of a `Store` with the supplied identifier.
    pub fn new(identifier: String) -> Store {
        return Store {
            identifier,
            data: HashMap::new(),
        }
    }

    /// Returns the identifier of the store.
    pub fn get_identifier(&self) -> &String {
        return &self.identifier
    }

    /// Sets a value in the store. A value is identified by a `String` value and can contain a type
    /// that is serializable.
    pub fn set<T: Serialize>(&mut self, key: String, value: &T) -> ProviderResult<()> {
        if self.data.contains_key(&key) {
            self.data.remove_entry(&key);
        }
        let serialized_content: Vec<u8> = serde_json::to_vec(value)?;
        self.data.insert(key, StoreContent::Value(serialized_content));
        Ok(())
    }

    /// Returns the data that is identified by the supplied key. Returns `Ok(None)` if no value
    /// matching the key was found. Will only return the value if it is not a nested store.
    pub fn get<T: DeserializeOwned>(&self, key: String) -> ProviderResult<Option<T>> {
        let data = self.data.get(&key);
        if data.is_none() {
            return Ok(None);
        }
        // Does not panic because we know from the check above that the data is not None
        let data = data.unwrap();

        if let StoreContent::Value(v) = data {
            let deserialized: T = serde_json::from_slice(v)?;
            return Ok(Some(deserialized));
        } else {
            Ok(None)
        }
    }

    /// Returns if the store contains a value with the supplied key.
    pub fn key_exists(&self, key: String) -> bool {
        return self.data.contains_key(&key);
    }

    pub fn get_nested_store(&mut self, key: String) -> Option<&mut Store> {
        match self.data.get_mut(&key) {
            Some(v) => match v {
                StoreContent::NestedStore(v) => {
                    Some(v)
                }
                _ => None,
            },
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_store() -> Store {
        let mut store = Store::new(String::from("test"));
        store.set("auth_token".to_string(), &"abc").unwrap();
        store.set("logged_in".to_string(), &true).unwrap();
        store.set("amount".to_string(), &0).unwrap();
        store
    }

    #[test]
    fn test_test_store_as_expected() {
        let store = get_test_store();
        let store_to_compare = Store {
            identifier: "test".to_string(),
            data: {
                let mut h = HashMap::new();
                h.insert("auth_token".to_string(), StoreContent::Value(vec![34, 97, 98, 99, 34]));
                h.insert("logged_in".to_string(), StoreContent::Value(vec![116, 114, 117, 101]));
                h.insert("amount".to_string(), StoreContent::Value(vec![48]));
                h
            },
        };
        assert_eq!(store_to_compare, store)
    }

    #[test]
    fn test_store_get_identifier() {
        let store = get_test_store();
        assert_eq!("test", store.get_identifier());
    }

    #[test]
    fn test_store_key_exists() {
        let store = get_test_store();
        assert!(store.key_exists("auth_token".to_string()));
        assert!(store.key_exists("logged_in".to_string()));
        assert!(store.key_exists("amount".to_string()));
        assert!(!store.key_exists("abc".to_string()));
        assert!(!store.key_exists("and_the_6".to_string()));
    }

    #[test]
    fn test_store_data_has_same_keys_as_hashmap() {
        let store = get_test_store();
        assert!(store.data.contains_key("auth_token"));
        assert!(store.data.contains_key("logged_in"));
        assert!(store.data.contains_key("amount"));
        assert!(!store.data.contains_key("abc"));
        assert!(!store.data.contains_key("and_the_6"));
    }

    #[test]
    fn test_store_set() {
        let mut store = Store::new(String::from("new"));
        store.set("test-key".to_string(), &true);
        store.set("test-key2".to_string(), &"henlo world");
        assert_eq!(Store {
            identifier: "new".to_string(),
            data: {
                let mut h = HashMap::new();
                h.insert("test-key".to_string(), StoreContent::Value(vec![116, 114, 117, 101]));
                h.insert("test-key2".to_string(), StoreContent::Value(vec![34, 104, 101, 110, 108, 111, 32, 119, 111, 114, 108, 100, 34]));
                h
            },
        }, store);
    }

    #[test]
    fn test_store_get() {
        let mut store = get_test_store();
        // Non-existent key
        assert_eq!(store.get::<String>("sdojfnjkalsdfjknaskjdnf".to_string()).unwrap(), None);

        // Normal values
        assert_eq!(store.get::<String>("auth_token".to_string()).unwrap(), Some(String::from("abc")));
        // The key in the HashMap (the data) should be the same
        assert!(store.data.contains_key("auth_token"));
        assert_eq!(store.get::<bool>("logged_in".to_string()).unwrap(), Some(true));
        assert!(store.data.contains_key("logged_in"));
        assert_eq!(store.get::<u32>("amount".to_string()).unwrap(), Some(0));
        assert!(store.data.contains_key("logged_in"));

        // Nested stores should not be returned
        store.data.insert("another-store".to_string(), StoreContent::NestedStore(Store {
            identifier: "sub-store".to_string(),
            data: {
                let mut h = HashMap::new();
                h.insert("sub-value".to_string(), StoreContent::Value(vec![48]));
                h
            },
        }));
        assert!(store.key_exists("another-store".to_string()));
        assert_eq!(store.get::<Store>("another-store".to_string()).unwrap(), None)
    }

    #[test]
    fn test_get_nested_store() {

    }
}