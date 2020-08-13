use dns_parser::Packet;
use seahash;
use state::Storage;
use state_list::StateList;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

pub static HARDMAPPED_DOMAINS: Storage<Mutex<HashMap<String, IpAddr>>> = Storage::new();

#[derive(Debug, std::clone::Clone, std::cmp::PartialEq)]
pub enum FResp {
    Allowed,
    StarAllowed,
    Hardcoded,
    Unknown,
    TMPList,
    Ignored,
    Hashed,
}

#[derive(std::clone::Clone, std::cmp::PartialEq)]
pub struct FilterResult {
    pub domain: String,
    pub filter: Option<String>,
    pub ip: Option<std::net::IpAddr>,
    pub state: FResp,
}

pub fn check_domain(
    domain: &String,
    qtype: dns_parser::QueryType,
    allow_list: &StateList<String>,
    tmp_list: &StateList<String>,
) -> FilterResult {
    if let Some(ip) = get_hardcoded_ip(&domain, qtype) {
        return FilterResult {
            domain: domain.to_string(),
            filter: Some(format!("{} {}", domain, ip)),
            ip: Some(ip),
            state: FResp::Hardcoded,
        };
    }

    return list_matches(domain, allow_list, tmp_list);
}

pub fn list_matches(
    domain: &str,
    allow_list: &StateList<String>,
    tmp_list: &StateList<String>,
) -> FilterResult {
    let mut filter_result = FilterResult {
        domain: domain.to_string(),
        filter: None,
        ip: None,
        state: FResp::Unknown,
    };
    let mut hashed_domain = String::new();

    //TMP list is probably shorter and should only contain complete domains
    if tmp_list.contains(&domain.to_string()) {
        filter_result.filter = Some(domain.to_string());
        filter_result.state = FResp::TMPList;
        return filter_result;
    }

    for entry in allow_list.get_entries() {
        if entry.starts_with("*.") {
            let matchme = entry.strip_prefix("*").unwrap();

            if domain.ends_with(matchme) {
                filter_result.state = FResp::StarAllowed;
                filter_result.filter = Some(entry);
            }
        } else if entry.starts_with("#") {
            if hashed_domain.is_empty() {
                hashed_domain = hash_domain(domain);
            }
            if hashed_domain == entry {
                filter_result.state = FResp::Hashed;
                filter_result.filter = Some(entry);
            }
        } else if entry.starts_with("!") {
            let mut mod_entry = entry.strip_prefix("!").unwrap();
            if mod_entry.starts_with("*.") {
                mod_entry = mod_entry.strip_prefix("*").unwrap();
            }

            if domain.ends_with(mod_entry) {
                filter_result.state = FResp::Ignored;
                filter_result.filter = Some(entry);
            }
        } else if entry == domain {
            filter_result.state = FResp::Allowed;
            filter_result.filter = Some(entry);
        }
    }
    return filter_result;
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

pub fn init_hard_mapped_hosts() -> HashMap<String, IpAddr> {
    let entries = "";
    return parse_host_list(entries);
}

pub fn get_hardcoded_ip(name: &String, qtype: dns_parser::QueryType) -> Option<IpAddr> {
    let mapped_ips = HARDMAPPED_DOMAINS
        .get_or_set(|| Mutex::new(init_hard_mapped_hosts()))
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

pub fn parse_host_list(str: &str) -> HashMap<String, IpAddr> {
    let mut mapped_ips = HashMap::<String, IpAddr>::new();

    for line in str.split("\n") {
        parse_config_line(line).map({
            |(domain, ip)| mapped_ips.insert(domain, ip)
        });
    }

    return mapped_ips;
}

pub fn parse_config_line(line: &str) -> Option<(String, IpAddr)>{
    let mut trimmed = line.trim();

    if !trimmed.is_empty() {
        if trimmed.starts_with("=") {
            trimmed = trimmed.strip_prefix("=").unwrap();
        }
        let split: Vec<&str> = trimmed.split_ascii_whitespace().collect();
        if split.len() == 2 {
            split[1].parse()
                .map(|ip: IpAddr| Some((split[0].to_string(), ip)))
                .unwrap_or_else( |_| {
                    None
                })
        } else {
            None
        }
    } else {
        None
    }
}

pub fn hash_domain(domain: &str) -> String {
    return format!("#{:16X}", seahash::hash(domain.as_bytes()));
}