mod parsers;

use crate::parsers::dotgov::parse_dotgov_domain_whois_info;
use crate::parsers::educause::parse_educause_domain_whois_info;
use crate::parsers::icann::parse_icann_domain_whois_info;
use crate::parsers::isnic::parse_isnic_domain_whois_info;
use crate::parsers::isocil::parse_isocil_domain_whois_info;
use crate::parsers::jprs::parse_jprs_domain_whois_info;
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
    Jprs,
    Krnic,
    NicIt,
    Nominet,
    Rnids,
    Tcinet,
}

#[derive(Debug, Eq, PartialEq)]
pub enum WhoIsThereError {
    UnsupportedTld,
}

pub struct DomainProps<'t> {
    pub domain_name: &'t str,
    pub whois_service: Option<WhoisService>,
    pub is_registered: Option<bool>,
    pub expiry_date: Option<String>,
    pub registrar: Option<&'t str>,
}

pub fn parse_domain_whois_info<'t>(
    domain_name: &'t str,
    whois_info: &'t str,
) -> Result<DomainProps<'t>, WhoIsThereError> {
    if domain_name.ends_with(".com") {
        return Ok(parse_icann_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".co") {
        return Ok(parse_icann_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".edu") {
        return Ok(parse_educause_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".fm") {
        return Ok(parse_icann_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".gov") {
        return Ok(parse_dotgov_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".il") {
        return Ok(parse_isocil_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".io") {
        return Ok(parse_icann_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".is") {
        return Ok(parse_isnic_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".it") {
        return Ok(parse_nicit_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".jp") {
        return Ok(parse_jprs_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".kr") {
        return Ok(parse_krnic_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".rs") {
        return Ok(parse_rnids_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".ru") {
        return Ok(parse_tcinet_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".social") {
        return Ok(parse_icann_domain_whois_info(whois_info));
    } else if domain_name.ends_with(".uk") {
        return Ok(parse_nominet_domain_whois_info(whois_info));
    }

    Err(WhoIsThereError::UnsupportedTld)
}
