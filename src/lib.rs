mod parsers;
mod registrars;
pub mod utils;

use crate::parsers::expiration_date::parse_expiration_date;
use crate::parsers::registrar::parse_registrar;
use crate::parsers::registration::parse_is_not_registered;
use crate::registrars::dotgov::parse_dotgov_registrar_domain_whois_info;
use crate::registrars::icann::parse_icann_registrar_domain_whois_info;
use crate::registrars::isnic::parse_isnic_registrar_domain_whois_info;
use crate::registrars::isocil::parse_isocil_registrar_domain_whois_info;
use crate::registrars::nicit::parse_nicit_registrar_domain_whois_info;
use crate::registrars::nominet::parse_nominet_registrar_domain_whois_info;
use crate::registrars::rnids::parse_rnids_registrar_domain_whois_info;

pub struct DomainProps<'t> {
    pub domain_name: &'t str,
    pub is_registered: Option<bool>,
    pub expiration_date: Option<String>,
    pub registrar: Option<&'t str>,
}

pub fn parse_domain_whois_info<'t>(domain_name: &'t str, whois_info: &'t str) -> DomainProps<'t> {
    if domain_name.ends_with(".com") {
        let mut domain_info = parse_icann_registrar_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".gov") {
        let mut domain_info = parse_dotgov_registrar_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".il") {
        let mut domain_info = parse_isocil_registrar_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".io") {
        let mut domain_info = parse_icann_registrar_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".is") {
        let mut domain_info = parse_isnic_registrar_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".it") {
        let mut domain_info = parse_nicit_registrar_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".rs") {
        let mut domain_info = parse_rnids_registrar_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".uk") {
        let mut domain_info = parse_nominet_registrar_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else {
        // // Everything else should fall onto ICANN
        let mut domain_info = parse_icann_registrar_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    }
}
