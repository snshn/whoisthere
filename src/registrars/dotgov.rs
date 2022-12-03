// .gov

use crate::{DomainPropStatus, DomainProps};

pub fn parse_dotgov_domain_whois_info<'a>(
    domain_name: &'a str,
    whois_info: &'a str,
) -> DomainProps<'a> {
    let mut domain_props = DomainProps {
        domain_name: domain_name,
        is_registered: None,
        expiration_date: None,
        registrar: None,
        status: DomainPropStatus::Unknown,
    };

    let lines = whois_info.lines();

    for line in lines {
        if line.eq_ignore_ascii_case(&format!("No match for \"{}\".", domain_name.to_uppercase())) {
            domain_props.is_registered = Some(false);
            break;
        }

        if line == "   Status: ACTIVE" {
            domain_props.is_registered = Some(true);
            break;
        }
    }

    return domain_props;
}
