use dns_strolch;
use std::env;
use log::LevelFilter;

fn main() {
    let args: Vec<String> = env::args().collect();
    simple_logging::log_to_stderr(LevelFilter::Info);

    dns_strolch::load_config_file(None);
    dns_strolch::init_allow_file(None);
    dns_strolch::load_hardcoded_file(None);

    if args.len() > 1 {
        let mut settings = dns_strolch::STROLCH_SETTINGS.get().lock().unwrap();
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

    dns_strolch::run_udp_server(dns_strolch::toastable::block_callback);
}
