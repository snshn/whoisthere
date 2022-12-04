mod parsers;

use crate::parsers::dotgov::parse_dotgov_domain_whois_info;
use crate::parsers::educause::parse_educause_domain_whois_info;
use crate::parsers::icann::parse_icann_domain_whois_info;
use crate::parsers::isnic::parse_isnic_domain_whois_info;
use crate::parsers::isocil::parse_isocil_domain_whois_info;
use crate::parsers::krnic::parse_krnic_domain_whois_info;
use crate::parsers::nicit::parse_nicit_domain_whois_info;
use crate::parsers::nominet::parse_nominet_domain_whois_info;
use crate::parsers::rnids::parse_rnids_domain_whois_info;
use crate::parsers::tcinet::parse_tcinet_domain_whois_info;

#[derive(Debug, Eq, PartialEq)]
pub enum WhoisService {
    Dotgov,
    Educause,
    Icann,
    Isnic,
    IsocIl,
    Krnic,
    NicIt,
    Nominet,
    Rnids,
    Tcinet,
}

pub struct DomainProps<'t> {
    pub domain_name: &'t str,
    pub whois_service: Option<WhoisService>,
    pub is_registered: Option<bool>,
    pub expiry_date: Option<String>,
    pub registrar: Option<&'t str>,
}

pub fn parse_domain_whois_info<'t>(domain_name: &'t str, whois_info: &'t str) -> DomainProps<'t> {
    if domain_name.ends_with(".com") {
        let mut domain_info = parse_icann_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".edu") {
        let mut domain_info = parse_educause_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".gov") {
        let mut domain_info = parse_dotgov_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".il") {
        let mut domain_info = parse_isocil_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".io") {
        let mut domain_info = parse_icann_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".is") {
        let mut domain_info = parse_isnic_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".it") {
        let mut domain_info = parse_nicit_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".kr") {
        let mut domain_info = parse_krnic_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".rs") {
        let mut domain_info = parse_rnids_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".ru") {
        let mut domain_info = parse_tcinet_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else if domain_name.ends_with(".uk") {
        let mut domain_info = parse_nominet_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    } else {
        // // Everything else should fall onto ICANN
        let mut domain_info = parse_icann_domain_whois_info(whois_info);
        if domain_info.domain_name == "" {
            domain_info.domain_name = domain_name;
        }
        return domain_info;
    }
}
