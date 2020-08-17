#![feature(str_strip)]
use dns_parser::Packet;
use state_list::StateList;
use std::net::UdpSocket;
use std::str;
use std::thread;
pub mod dns_actions;
mod dns_cache;
pub mod domain_filter;
use dns_cache::DNSCache;
use domain_filter::FResp;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
extern crate tld;
use std::sync::Mutex;
pub mod toastable;

static DNS_SERVER_UDP: &str = "1.1.1.1:53";
/*
static DNS_SERVER_DOH: &str = "doh-de.blahdns.com";
static DNS_SERVER_DOH_IP: &str = "159.69.198.101";
static DNS_SERVER_DOH_PATH: &str = "/dns-query?dns=";
*/
static DNS_SERVER_DOH: &str = "cloudflare-dns.com";
static DNS_SERVER_DOH_IP: &str = "104.16.249.249";
static DNS_SERVER_DOH_PATH: &str = "/dns-query?dns=";

type RequestCallback = fn(arguments: &str);

static STALL_METHOD: &str = "nothing";
pub static ALLOW_LIST: StateList<String> = StateList::new();
pub static TMP_LIST: StateList<String> = StateList::new();
pub static DNS_CACHE: DNSCache = DNSCache::new();
pub static CALLBACKS: StateList<FilterCallback> = StateList::new();

#[derive(std::clone::Clone, std::cmp::PartialEq)]
pub struct FilterCallback {
    domain: String,
    filter: String,
    state: domain_filter::FResp,
}

pub fn init_empty() {
    ALLOW_LIST.init_empty();
    TMP_LIST.init_empty();
    DNS_CACHE.init();
}

pub fn init_string(rules: String) {
    ALLOW_LIST.init_string(rules);
    TMP_LIST.init_empty();
    DNS_CACHE.init();

    //extract hardcoded ips from allow list
    for entry in ALLOW_LIST.get_entries() {
        if entry.starts_with("=") {
            add_hardcoded_ip(entry.as_str());
        }
    }
}

pub fn init_file(dns_file: String) {
    ALLOW_LIST.load(dns_file);
    TMP_LIST.init_empty();
    DNS_CACHE.init();
}

pub fn init_hardmapped(entries: &str) {
    //why does HARDMAPPED_DOMAINS live in domain_filter, while other lists live here ? :D
    domain_filter::HARDMAPPED_DOMAINS.set(Mutex::new(domain_filter::parse_host_list(entries)));
}

pub fn run_udp_server(bind_to: &str, callback: RequestCallback) {
    let arg = "DOH";

    let socket = UdpSocket::bind(bind_to).unwrap_or_else(|e| {
        println!("Unable to open socket:\n {}", e);
        std::process::exit(1);
    });

    println!("{:<12} : {}", "Listening", bind_to);
    let mut request_buf = [0; 512];
    loop {
        match socket.recv_from(&mut request_buf) {
            Ok((size, src)) => {
                let socketx = socket.try_clone().unwrap();

                thread::spawn(move || {
                    check_dns_request(&request_buf[0..size].to_vec(), &socketx, src, arg, callback, logs);
                });
            }
            Err(e) => {
                eprintln!("{:<12} : {:?}", "con bungled", e);
            }
        }
    }
}

pub fn logs(arguments: &str){
    println!("{}", arguments);
}

pub fn check_dns_request(
    dns_question: &Vec<u8>,
    answer_socket: &UdpSocket,
    src: SocketAddr,
    arg: &str,
    callback: RequestCallback,
    log: RequestCallback,
) {
    let question_pkt = dns_actions::parse_dns_packet(dns_question);
    let domain = domain_filter::find_domain_name(&question_pkt).unwrap();
    let qtype = question_pkt.questions[0].qtype;

    //check_domain
    let filter_result = domain_filter::check_domain(&domain, qtype, &ALLOW_LIST, &TMP_LIST);
    log_request_state(
        format!("{:?}", filter_result.state).as_str(),
        src.ip(),
        &domain,
        qtype,
        log,
    );

    //handle filter result 
    match filter_result.state {
        FResp::Hardcoded => {
            let dns_answer = dns_actions::local_answer(
                &question_pkt,
                filter_result.ip.unwrap(),
                &domain,
                i32::max_value() / 3,
            );
            dns_actions::dns_response(&dns_answer, &answer_socket, src);
        }
        FResp::Ignored => {
            refuse_query_method(&question_pkt, &answer_socket, src, domain, "null_ip");
        }
        FResp::Unknown => {
            callback(&domain);
            refuse_query(&question_pkt, &answer_socket, src, domain);
        }
        _ => {
            //ALLOWED
            answer_dns_question(domain, &dns_question, answer_socket, src, arg, qtype, log);
        }
    }
}

fn answer_dns_question(
    domain: String,
    dns_question: &Vec<u8>,
    answer_socket: &UdpSocket,
    src: SocketAddr,
    arg: &str,
    qtype: dns_parser::QueryType,
    log: RequestCallback,
) {
    //Check cache first, after that use method from arg
    let dns_answer = match DNS_CACHE.lookup_packet(&dns_question) {
        Some(cache_answer) => {
            log_request_state("[CACHE] ret", src.ip(), &domain, qtype, log);
            dns_actions::fix_up_cache_response(dns_question, cache_answer)
        }
        None => {
            let none_cache_answer = match arg {
                "DOH" => {
                    log_request_state("[DOH] lookup", src.ip(), &domain, qtype, log);
                    dns_actions::doh_lookup(
                        DNS_SERVER_DOH,
                        DNS_SERVER_DOH_IP,
                        DNS_SERVER_DOH_PATH,
                        dns_question,
                    )
                }
                _ => {
                    log_request_state("[UDP] lookup", src.ip(), &domain, qtype, log);
                    dns_actions::udp_lookup(DNS_SERVER_UDP, dns_question)
                }
            };
            DNS_CACHE.add_packet(&none_cache_answer);
            none_cache_answer
        }
    };

    dns_actions::dns_response(&dns_answer, &answer_socket, src);
}

fn log_request_state(state: &str, ip: IpAddr, domain: &String, qtype: dns_parser::QueryType, log: RequestCallback) {
    log(format!(
        "{:<12} : {:<22} : [{:>4}] {}",
        state,
        ip,
        format!("{:?}", qtype),
        domain
    ).as_str());
}

fn refuse_query_method(
    pkt: &Packet,
    socketx: &UdpSocket,
    src: SocketAddr,
    domain: String,
    method: &str,
) {
    //log_request_state("refusing", src.ip(), &domain, pkt.questions[0].qtype);

    if method == "nothing" {
        return;
    }

    let dns_answer = match method {
        "truncated" => dns_actions::refuse_query_truncated_answer(pkt),
        "null_ip" => {
            let ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
            dns_actions::local_answer(&pkt, ip, &domain, 60 * 30)
        }
        _ => dns_actions::name_error_answer(&pkt, "0.0.0.0".parse().unwrap(), &domain),
    };

    dns_actions::dns_response(&dns_answer, &socketx, src);
}

fn refuse_query(pkt: &Packet, socketx: &UdpSocket, src: SocketAddr, domain: String) {
    refuse_query_method(pkt, socketx, src, domain, STALL_METHOD);
}

pub fn add_hardcoded_ip(str: &str){
    domain_filter::parse_config_line(str).map({
        |(domain, ip)| 
        //TODO: ipv6???
        domain_filter::HARDMAPPED_DOMAINS
        .get_or_set(|| Mutex::new(domain_filter::init_hard_mapped_hosts())).lock().unwrap().insert(domain, ip)
    });
}

pub fn remove_hardcoded_ip(str: &str){
    domain_filter::parse_config_line(str).map({
        |(domain, _ip)| 
        //TODO: ipv6???
        domain_filter::HARDMAPPED_DOMAINS
        .get_or_set(|| Mutex::new(domain_filter::init_hard_mapped_hosts())).lock().unwrap().remove(&domain)
    });
}

pub fn dot_reverse(str: &String) -> String {
    let mut split = str.split('.').collect::<Vec<&str>>();
    split.reverse();
    return split.join(".");
}