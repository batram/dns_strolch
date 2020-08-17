use dns_parser::Packet;
use dns_parser::{QueryType, ResponseCode};
use state::Storage;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct DNSCache {
    cache_ttl: u64,
    cache_map: Storage<Mutex<HashMap<CacheKey, CacheEntry>>>,
}

pub struct CacheEntry {
    packet: Vec<u8>,
    timestamp: Instant,
}

#[derive(Hash, Eq, PartialEq)]
pub struct CacheKey {
    domain: String,
    qtype: u8,
}

impl DNSCache {
    pub const fn new() -> DNSCache {
        DNSCache {
            cache_ttl: 60 * 60,
            cache_map: Storage::new(),
        }
    }

    pub fn init(&self) {
        let dns_hash = HashMap::new();
        self.cache_map.set(Mutex::new(dns_hash));
    }

    pub fn add_item(&self, key: CacheKey, pkt: Vec<u8>) {
        let timestamp = Instant::now();

        let mut dns_hash = self.cache_map.get().lock().unwrap();
        dns_hash.insert(
            key,
            CacheEntry {
                packet: pkt,
                timestamp: timestamp,
            },
        );
    }

    pub fn add_packet(&self, pkt_buf: &Vec<u8>) {
        match DNSCache::cache_key(pkt_buf) {
            Some(key) => self.add_item(key, pkt_buf.to_vec()),
            None => {}
        }
    }

    pub fn cacheable(qtype: QueryType) -> bool {
        return match qtype {
            QueryType::CNAME | QueryType::AAAA | QueryType::A => true,
            _ => false,
        };
    }

    pub fn cache_key(pkt_buf: &Vec<u8>) -> Option<CacheKey> {
        let parse_res = Packet::parse(&pkt_buf);

        match parse_res {
            Ok(pkt) => {
                if pkt.questions.len() >= 1 && pkt.header.response_code == ResponseCode::NoError {
                    let firstq = pkt.questions.first().unwrap();
                    let domain = format!("{}", firstq.qname);
        
                    return match firstq.qtype {
                        x if DNSCache::cacheable(x) => Some(CacheKey {
                            domain: domain,
                            qtype: x as u8,
                        }),
                        _ => None,
                    };
                }
                None
            },
            Err(e) => {
                warn!("DNS parser error: {:?}", e);
                None
            }
        }
    }

    pub fn remove(
        &self,
        key: &CacheKey,
        open_hash: Option<std::sync::MutexGuard<'_, HashMap<CacheKey, CacheEntry>>>,
    ) {
        match open_hash {
            Some(mut x) => {
                x.remove_entry(key);
            }
            None => {
                let mut dns_hash = self.cache_map.get().lock().unwrap();
                dns_hash.remove_entry(key);
            }
        };
    }

    pub fn lookup_packet(&self, pkt_buf: &Vec<u8>) -> Option<Vec<u8>> {
        let dns_hash = self.cache_map.get().lock().unwrap();

        match DNSCache::cache_key(pkt_buf) {
            Some(key) => match dns_hash.get(&key) {
                Some(entry) => {
                    let duration = entry.timestamp.elapsed();

                    if duration > Duration::from_secs(self.cache_ttl) {
                        self.remove(&key, Some(dns_hash));
                        return None;
                    }
                    return Some(entry.packet.clone());
                }
                _ => return None,
            },
            _ => return None,
        }
    }
}
