// ISOC-IL: .il

use crate::DomainProps;

pub fn parse_isocil_registrar_domain_whois_info<'a>(
    domain_name: &'a str,
    whois_info: &'a str,
) -> DomainProps<'a> {
    let mut domain_props = DomainProps {
        domain_name: domain_name,
        is_registered: None,
        expiration_date: None,
        registrar: None,
    };

    let lines = whois_info.lines();

    // Domain not registered, return basic info
    if lines.clone().count() == 15 {
        domain_props.is_registered = Some(false);
        return domain_props;
    } else {
        domain_props.is_registered = Some(true);
    }

    return domain_props;
}
