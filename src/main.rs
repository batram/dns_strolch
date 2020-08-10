#![feature(str_strip)]
use dns_parser::Packet;
use state_list::StateList;
use std::net::UdpSocket;
use std::str;
use std::thread;
mod dns_actions;
mod dns_cache;
mod domain_filter;
use dns_cache::DNSCache;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
extern crate tld;
use std::env;

#[cfg(all(windows))]
use toast_notifications;

static DNS_SERVER_UDP: &str = "1.1.1.1:53";
/*
static DNS_SERVER_DOH: &str = "doh-de.blahdns.com";
static DNS_SERVER_DOH_IP: &str = "159.69.198.101";
static DNS_SERVER_DOH_PATH: &str = "/dns-query?dns=";
*/
static DNS_SERVER_DOH: &str = "cloudflare-dns.com";
static DNS_SERVER_DOH_IP: &str = "104.16.249.249";
static DNS_SERVER_DOH_PATH: &str = "/dns-query?dns=";

static STALL_METHOD: &str = "nothing";
static ALLOW_LIST: StateList<String> = StateList::new();
static TMP_LIST: StateList<String> = StateList::new();
static DNS_CACHE: DNSCache = DNSCache::new();

fn main() {
    static DNSLIST_FILE_PATH: &str = "dns_list.txt";
    ALLOW_LIST.load(DNSLIST_FILE_PATH);
    TMP_LIST.init_empty();
    DNS_CACHE.init();

    ctrlc::set_handler(|| {
        ALLOW_LIST.sort_dedup_list({
            |a, b| domain_filter::dot_reverse(a).cmp(&domain_filter::dot_reverse(b))
        });
        ALLOW_LIST.save_matching(|x| !x.starts_with("||"));
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let arg = "DOH";
    let mut bind_to = "0.0.0.0:53";

    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        bind_to = args[1].as_str();
    }
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
                    handle_dns_request(&request_buf[0..size].to_vec(), &socketx, src, arg);
                });
            }
            Err(e) => {
                eprintln!("{:<12} : {}", "con bungled", e);
            }
        }
    }
}

fn handle_dns_request(
    dns_question: &Vec<u8>,
    answer_socket: &UdpSocket,
    src: SocketAddr,
    arg: &str,
) {
    let question_pkt = dns_actions::parse_dns_packet(dns_question);
    let mut domain = domain_filter::find_domain_name(&question_pkt).unwrap();
    let qtype = question_pkt.questions[0].qtype;
    domain = domain_filter::remove_wait_cname(domain);

    //log_request_state("new_request", src.ip(), &domain, qtype);

    if let Some(ip) = domain_filter::get_hardcoded_ip(&domain, qtype) {
        log_request_state("hardcoded", src.ip(), &domain, qtype);
        let dns_answer =
            dns_actions::resolved_local_answer(&question_pkt, ip, &domain, i32::max_value() / 3);
        dns_actions::dns_response(&dns_answer, &answer_socket, src);
        return;
    }

    let (reason, allowed) = domain_filter::allow_request(&domain, &ALLOW_LIST, &TMP_LIST);
    if !allowed {
        //Request blocked (not in ALLOW_LIST or TMP_LIST)

        if domain_filter::domain_ignored(&domain.as_str(), &ALLOW_LIST) {
            //Don't show notifications for ignored domains
            log_request_state("ignored", src.ip(), &domain, qtype);
            refuse_query_method(&question_pkt, &answer_socket, src, domain, "null_ip");
            return;
        }
        log_request_state(reason, src.ip(), &domain, qtype);

        let template = get_toast_template(&domain);

        //Show windows TOAST notification
        //TODO: move to notify-rust lib and wurschtle our wincode in there
        #[cfg(all(windows, not(target_os = "linux")))]
        toast_notifications::show_deduped_message(&domain, template.as_str(), toast_callback, 20);

        refuse_query(&question_pkt, &answer_socket, src, domain);
        return;
    } else {
        answer_dns_question(domain, &dns_question, answer_socket, src, arg, qtype);
    }
}

fn log_request_state(state: &str, ip: IpAddr, domain: &String, qtype: dns_parser::QueryType) {
    println!(
        "{:<12} : {:<22} : [{:>4}] {}",
        state,
        ip,
        format!("{:?}", qtype),
        domain
    );
}

fn answer_dns_question(
    domain: String,
    dns_question: &Vec<u8>,
    answer_socket: &UdpSocket,
    src: SocketAddr,
    arg: &str,
    qtype: dns_parser::QueryType,
) {
    //Check cache first, after that use method from arg
    let dns_answer = match DNS_CACHE.lookup_packet(&dns_question) {
        Some(cache_answer) => {
            log_request_state("[CACHE] ret", src.ip(), &domain, qtype);
            dns_actions::fix_up_cache_response(dns_question, cache_answer)
        }
        None => {
            let none_cache_answer = match arg {
                "DOH" => {
                    log_request_state("[DOH] lookup", src.ip(), &domain, qtype);
                    dns_actions::doh_lookup(
                        DNS_SERVER_DOH,
                        DNS_SERVER_DOH_IP,
                        DNS_SERVER_DOH_PATH,
                        dns_question,
                    )
                }
                _ => {
                    log_request_state("[UDP] lookup", src.ip(), &domain, qtype);
                    dns_actions::udp_lookup(DNS_SERVER_UDP, dns_question)
                }
            };
            DNS_CACHE.add_packet(&none_cache_answer);
            none_cache_answer
        }
    };

    dns_actions::dns_response(&dns_answer, &answer_socket, src);
}

fn toast_callback(arguments: &str) {
    let split = arguments.split("*").collect::<Vec<&str>>();
    if split.len() != 2 {
        unreachable!("don't understand this message: {}", arguments);
    }
    let fun = split[0];
    let bdecoded = base64::decode(split[1]).unwrap();
    let domain = str::from_utf8(bdecoded.as_slice()).unwrap();

    match fun {
        "allow" => {
            ALLOW_LIST.add_item(domain.to_string());
            //TODO?: Store questions and resolve at this point?
        }
        "ignore" => {
            ALLOW_LIST.add_item("!".to_string() + domain);
        }
        "top" => match domain_filter::top_level_filter(domain) {
            Ok(filter) => {
                ALLOW_LIST.add_item(filter);
            }
            Err(e) => panic!(e),
        },
        "tmp" => {
            //will not be persisted
            //TODO: Addjust and track TTL
            TMP_LIST.add_item(domain.to_string());
        }
        f => println!("can't do {} yet!", f),
    }
}

pub fn get_toast_template(domain: &str) -> String {
    //TODO: Make XML Safe text insertions, since DNS names can contain anything :D
    let enced = base64::encode(domain);
    let dm = domain.replace(|c: char| !c.is_ascii() || c == '<' || c == '>', "_");


    return format!(
        "<toast launch=\"launch*{enced}\">
            <visual>
            <binding template =\"ToastGeneric\">
            <text>DNS BLOCKED: {domain}</text>
            </binding>
            </visual>
            <actions>
            <action activationType=\"background\" content=\"ALLOW\" arguments=\"allow*{enced}\"/>
            <action activationType=\"background\" content=\"ALLOW TOP\" arguments=\"top*{enced}\"/>
            <action activationType=\"background\" content=\"TMP\" arguments=\"tmp*{enced}\"/>
            <action activationType=\"background\" content=\"IGNORE\" arguments=\"ignore*{enced}\"/>
            </actions>
        </toast>",
        enced = enced,
        domain = dm
    );
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
        "CNAME" => dns_actions::refuse_query_cname_answer(pkt, domain),
        "truncated" => dns_actions::refuse_query_truncated_answer(pkt),
        "null_ip" => {
            let ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
            dns_actions::resolved_local_answer(&pkt, ip, &domain, 60 * 30)
        }
        _ => dns_actions::refuse_query_cname_answer(pkt, domain),
    };

    dns_actions::dns_response(&dns_answer, &socketx, src);
}

fn refuse_query(pkt: &Packet, socketx: &UdpSocket, src: SocketAddr, domain: String) {
    refuse_query_method(pkt, socketx, src, domain, STALL_METHOD);
}
