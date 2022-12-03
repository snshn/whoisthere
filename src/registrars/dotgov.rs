// DOTGOV: .gov

use crate::DomainProps;

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
    }

    return domain_props;
}
