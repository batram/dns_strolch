extern crate windows_service;
#[macro_use]
extern crate log;

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    dnsstrolch_service::run()
}

#[cfg(not(windows))]
fn main() {
    panic!("This program is only intended to run on Windows.");
}

#[cfg(windows)]
mod dnsstrolch_service {
    use log::LevelFilter;
    use simple_logging;
    use std::env;
    use std::net::UdpSocket;
    use std::str;
    use std::thread;
    use std::{ffi::OsString, sync::mpsc, time::Duration};

    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher, Result,
    };

    const SERVICE_NAME: &str = "dnsstrolch_service";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    pub fn run() -> Result<()> {
        // Register generated `ffi_service_main` with the system and start the service, blocking
        // this thread until the service is stopped.
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }
    define_windows_service!(ffi_service_main, my_service_main);

    pub fn my_service_main(_arguments: Vec<OsString>) {
        if let Err(_e) = run_service() {
            // Handle the error, by logging or something.
        }
    }

    pub fn run_service() -> Result<()> {
        //move cwd to path of exe, to look for files
        let root = ::std::env::current_exe().unwrap().with_file_name("");
        env::set_current_dir(&root).unwrap();

        simple_logging::log_to_file("loggy", LevelFilter::Info).unwrap();

        // Create a channel to be able to poll a stop event from the service worker loop.
        let (shutdown_tx, shutdown_rx) = mpsc::channel();

        // Define system service event handler that will be receiving service events.
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                // Notifies a service to report its current status information to the service
                // control manager. Always return NoError even if not implemented.
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,

                // Handle stop or shotdown
                ServiceControl::Stop | ServiceControl::Preshutdown  => {
                    shutdown_tx.send(()).unwrap();
                    ServiceControlHandlerResult::NoError
                }

                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        // Register system service event handler.
        // The returned status handle should be used to report service status changes to the system.
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

        // Tell the system that service is running
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        dns_strolch::load_config_file(None);
        dns_strolch::init_allow_file(None);
        dns_strolch::load_hardcoded_file(None);

        let settings = dns_strolch::STROLCH_SETTINGS.get().lock().unwrap().clone();

        let socket = UdpSocket::bind(settings.bind_to.as_str()).unwrap_or_else(|e| {
            warn!("Unable to open socket:\n {}", e);
            std::process::exit(1);
        });

        //Set a read timeout so we can still get service signals
        socket
            .set_read_timeout(Some(Duration::new(1, 100)))
            .unwrap_or_else(|e| {
                warn!("Unable to set read_timeout:\n {}", e);
                std::process::exit(1);
            });

        info!("{:<12} : {}", "Listening", settings.bind_to);
        let mut request_buf = [0; 512];
        loop {
            match socket.recv_from(&mut request_buf) {
                Ok((size, src)) => {
                    let socketx = socket.try_clone().unwrap();
                    thread::spawn(move || {
                        dns_strolch::check_dns_request(
                            &request_buf[0..size].to_vec(),
                            &socketx,
                            src,
                            dns_strolch::toastable::block_callback,
                        );
                    });
                }
                Err(e) => {
                    match e.kind() {
                        std::io::ErrorKind::TimedOut => {
                            /* ignore timeouts, we want this to happen */
                        }
                        _ => info!("{:<12} : {:#?} -- {}", "con bungled", e.kind(), e),
                    }
                }
            }

            // Poll shutdown event.
            match shutdown_rx.recv_timeout(Duration::new(0, 1)) {
                // Break the loop either upon stop or channel disconnect
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,

                // Continue work if no events were received within the timeout
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            };
        }
        info!("{:<12}", "Service stopping");

        //save list on service exit
        dns_strolch::ALLOW_LIST
            .sort_dedup_list(|a, b| dns_strolch::dot_reverse(a).cmp(&dns_strolch::dot_reverse(b)));
        dns_strolch::ALLOW_LIST.save_matching(|x| !x.starts_with("||"));

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        Ok(())
    }
}
