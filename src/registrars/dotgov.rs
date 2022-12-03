// DOTGOV: .gov

use crate::DomainProps;
use regex::Regex;

pub fn parse_dotgov_registrar_domain_whois_info<'a>(whois_info: &'a str) -> DomainProps<'a> {
    let mut domain_props = DomainProps {
        domain_name: "",
        is_registered: None,
        expiry_date: None,
        registrar: None,
    };

    let lines = whois_info.lines();

    for line in lines {
        if line.starts_with("No match for \"") && line.ends_with("\".") {
            domain_props.is_registered = Some(false);
            break;
        }

        if line == "   Status: ACTIVE" {
            domain_props.is_registered = Some(true);
            break;
        }

        if line.starts_with("   Domain Name: ") {
            let re = Regex::new(r"\s+Domain Name:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                domain_props.domain_name = caps.get(1).unwrap().as_str();
            }
            continue;
        }
    }

    return domain_props;
}
