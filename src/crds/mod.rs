// crds -> conflict-free replicated data store
use std::collections::HashMap;

pub enum CrdsValue {
    ContactInfo {
        ip: String,
        port: u16
    },
    Vote {
        slot: u64
    },
    EpochSlots {
        slots: Vec<u64>
    }
}

pub struct CrdsEntry {
    pub value: CrdsValue,
    pub timestamp: u64,
    pub pubkey: String
}

pub struct CrdsTable {
    pub entries: HashMap<String, CrdsEntry>,
}

impl CrdsValue {
    pub fn label(&self) -> &str {
        match self {
            CrdsValue::ContactInfo { .. } => "ContactInfo",
            CrdsValue::Vote { .. } => "Vote",
            CrdsValue::EpochSlots { .. } => "EpochSlots",
        }
    }
}

impl CrdsTable {
    pub fn new() -> Self {
        CrdsTable {
            entries: HashMap::new(),
        }
    }
    
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }
    
    pub fn insert(&mut self, pubkey: String, value: CrdsValue, timestamp: u64) {
        let key = format!("{}_{}", pubkey, value.label());
        
        match self.entries.get(&key) {
            Some(existing) => {
                if timestamp > existing.timestamp {
                    self.entries.insert(key, CrdsEntry { value, timestamp, pubkey });
                }
            }
            None => {
                self.entries.insert(key, CrdsEntry { value, timestamp, pubkey });
            }
        }
    }
    
    pub fn get(&self, key: &str) -> Option<&CrdsEntry> {
        self.entries.get(key)
    }
    
    pub fn purge_expired(&mut self, current_time: u64, max_age: u64) {
        self.entries.retain(|_key, entry| {
            current_time - entry.timestamp <= max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_insert_and_get() {
        let mut table = CrdsTable::new();
        table.insert(
            "ABC123".into(), 
            CrdsValue::Vote {
                slot: 100
            }, 
            1000
        );
        
        assert!(table.get("ABC123_Vote").is_some());
        assert!(table.get("ABC123_ContactInfo").is_none());
    }
    
    #[test]
    fn test_higher_timestamp_wins() {
        let mut table = CrdsTable::new();
        table.insert("ABC123".into(), CrdsValue::Vote { slot: 100 }, 1000);
        table.insert("ABC123".into(), CrdsValue::Vote { slot: 200 }, 2000);
        let entry = table.get("ABC123_Vote").unwrap();
        assert_eq!(entry.timestamp, 2000);
    }
    
    #[test]
    fn test_lower_timestamp_ignored() {
        let mut table = CrdsTable::new();
        table.insert("ABC123".into(), CrdsValue::Vote { slot: 200 }, 2000);
        table.insert("ABC123".into(), CrdsValue::Vote { slot: 100 }, 1000);
        let entry = table.get("ABC123_Vote").unwrap();
        assert_eq!(entry.timestamp, 2000);
    }
    
    #[test]
    fn test_purge_expired() {
        let mut table = CrdsTable::new();
        table.insert("ABC123".into(), CrdsValue::Vote { slot: 100 }, 1000);
        table.insert("DEF456".into(), CrdsValue::Vote { slot: 200 }, 5000);
        table.purge_expired(6000, 2000);
        assert!(table.get("ABC123_Vote").is_none());
        assert!(table.get("DEF456_Vote").is_some());
    }
}