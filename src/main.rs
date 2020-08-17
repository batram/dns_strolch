use dns_strolch;
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut bind_to = "0.0.0.0:53";

    if args.len() > 1 {
        bind_to = args[1].as_str();
    }

    let dns_list_file_path: String = "dns_list.txt".to_string();
    dns_strolch::init_file(dns_list_file_path);

    ctrlc::set_handler(|| {
        dns_strolch::ALLOW_LIST.sort_dedup_list({
            |a, b| dns_strolch::dot_reverse(a).cmp(&dns_strolch::dot_reverse(b))
        });
        dns_strolch::ALLOW_LIST.save_matching(|x| !x.starts_with("||"));
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let hardcoded_file_path = "hardcoded.txt";
    let entries = fs::read_to_string(hardcoded_file_path).unwrap_or_else(|e| {
        println!("Couldn't load hardcoded domains: {} {}", hardcoded_file_path, e);
        return String::new();
    });

    dns_strolch::init_hardmapped(entries.as_str());

    dns_strolch::run_udp_server(bind_to, dns_strolch::block_callback);
}
