use dns_strolch;
use std::env;
use std::fs;
use log::LevelFilter;

fn main() {
    let args: Vec<String> = env::args().collect();
    simple_logging::log_to_stderr(LevelFilter::Info);


    dns_strolch::init_allow_file(None);
    let mut settings = dns_strolch::STROLCH_SETTINGS.get().clone();

    if args.len() > 1 {
        settings.bind_to = args[1].clone();
    }

    ctrlc::set_handler(|| {
        dns_strolch::ALLOW_LIST.sort_dedup_list({
            |a, b| dns_strolch::dot_reverse(a).cmp(&dns_strolch::dot_reverse(b))
        });
        dns_strolch::ALLOW_LIST.save_matching(|x| !x.starts_with("||"));
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let hardcoded_file_path = settings.hardcoded_path.clone();
    let entries = fs::read_to_string(hardcoded_file_path.clone()).unwrap_or_else(|e| {
        println!(
            "Couldn't load hardcoded domains: {} {}",
            hardcoded_file_path, e
        );
        return String::new();
    });
    dns_strolch::STROLCH_SETTINGS.set(settings);

    dns_strolch::init_hardmapped(entries.as_str());
    dns_strolch::run_udp_server(dns_strolch::toastable::block_callback);
}
