use crate::{ALLOW_LIST, TMP_LIST};
use std::str;

#[cfg(all(windows))]
use toast_notifications;

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
        "top" => match top_level_filter(domain) {
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

pub fn block_callback(domain: &str) {
    let template = get_toast_template(&domain);

    //Show windows TOAST notification
    //TODO: move to notify-rust lib and wurschtle our wincode in there
    #[cfg(all(windows, not(target_os = "linux")))]
    toast_notifications::show_deduped_message(
        &String::from(domain),
        template.as_str(),
        toast_callback,
        20,
    );
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
