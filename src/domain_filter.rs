use dns_parser::Packet;
use state::Storage;
use state_list::StateList;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::sync::Mutex;
use std::{thread, time};
use tld;

static HARDMAPPED_DOMAINS: Storage<Mutex<HashMap<String, IpAddr>>> = Storage::new();

pub fn domain_ignored(domain: &str, allow_list: &StateList<String>) -> bool {
    for entry in allow_list.get_entries() {
        if entry.starts_with("!") {
            let mut entry = entry.strip_prefix("!").unwrap();
            if entry.starts_with("*.") {
                entry = entry.strip_prefix("*").unwrap();
            }

            if domain.ends_with(entry) {
                return true;
            }
        }
    }
    return false;
}

pub fn domain_matches_star(domain: &str, allow_list: &StateList<String>) -> bool {
    for entry in allow_list.get_entries() {
        if entry.starts_with("*.") {
            let matchme = entry.strip_prefix("*").unwrap();

            if domain.ends_with(matchme) {
                return true;
            }
        }
    }
    return false;
}

pub fn find_domain_name(pkt: &Packet) -> Option<String> {
    if pkt.questions.len() >= 1 {
        let firstq = pkt.questions.first().unwrap();
        return Some(format!("{}", firstq.qname));
    }

    if pkt.answers.len() >= 1 {
        let firsta = pkt.answers.first().unwrap();
        return Some(format!("{}", firsta.name));
    }
    return None;
}

pub fn parse_host_list(str: &str) -> HashMap<String, IpAddr> {
    let mut mapped_ips = HashMap::<String, IpAddr>::new();

    for line in str.split("\n") {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let split: Vec<&str> = trimmed.split_ascii_whitespace().collect();
        if split.len() == 2 {
            split[1]
                .parse()
                .map(|ip| mapped_ips.insert(split[0].to_string(), ip))
                .unwrap_or_else(|e| {
                    eprintln!("wuups, failed to parse ip: {:?} {:?}", split, e);
                    None
                });
        } else {
            eprintln!("wuups, don't understand config: {:?}", split);
        }
    }

    return mapped_ips;
}

pub fn get_hard_mapped_hosts() -> HashMap<String, IpAddr> {
    let file_path = "hardcoded.txt";
    let entries = fs::read_to_string(file_path).unwrap_or_else(|e| {
        println!("Couldn't load hardcoded domains: {} {}", file_path, e);
        return String::new();
    });

    return parse_host_list(entries.as_str());
}

pub fn get_hardcoded_ip(name: &String, qtype: dns_parser::QueryType) -> Option<IpAddr> {
    let mapped_ips = HARDMAPPED_DOMAINS
        .get_or_set(|| Mutex::new(get_hard_mapped_hosts()))
        .lock()
        .unwrap();

    let ipv6_option = "ipv6::".to_string() + name.as_str();

    let key = match qtype {
        dns_parser::QueryType::AAAA => &ipv6_option,
        dns_parser::QueryType::A => name,
        _ => return None,
    };

    return mapped_ips.get(key).map(|ip| ip.clone());
}

pub fn remove_wait_cname(mut domain: String) -> String {
    if domain.ends_with(".plzwait") {
        thread::sleep(time::Duration::from_millis(1000));
        domain = domain.strip_suffix(".plzwait").unwrap().to_string();
    }

    return domain;
}

pub fn allow_request(
    domain: &String,
    allow_list: &StateList<String>,
    tmp_list: &StateList<String>,
) -> (&'static str, bool) {
    if allow_list.contains(&domain) {
        return ("allowed", true);
    }

    if tmp_list.contains(&domain) {
        return ("tmplist", true);
    }

    if domain_matches_star(&domain.as_str(), allow_list) {
        return ("star_allowed", true);
    }

    return ("unknown", false);
}

pub fn dot_reverse(str: &String) -> String {
    let mut split = str.split('.').collect::<Vec<&str>>();
    split.reverse();
    return split.join(".");
}

pub fn top_level_filter(domain: &str) -> Result<String, String> {
    let split = domain.split('.').collect::<Vec<&str>>();
    let vlen = split.len();
    if vlen >= 3 {
        let top2 = split[vlen - 2].to_string() + "." + split[vlen - 1];
        if tld::exist(top2.as_str()) {
            let mdomain = "*.".to_string() + split[vlen - 3] + "." + top2.as_str();
            return Ok(mdomain.to_string());
        }
    }
    if vlen >= 2 {
        let top1 = split.last().unwrap();
        if tld::exist(top1) {
            let mdomain = "*.".to_string() + split[vlen - 2] + "." + top1;
            return Ok(mdomain.to_string());
        }
    }

    return Err(format!("Can't determine top level domain of {}", domain));
}
