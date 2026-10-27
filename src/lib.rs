#![doc = include_str!("../README.md")]

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

/// The registry (WHOIS service) whose response format was used for parsing
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

/// Lifecycle stage of a registered domain
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DomainStatus {
    Active,                  // Bought and paid for (unexpired)
    ExpiredGracePeriod,      // Expired (typically day 1–30, sometimes 1–45)
    ExpiredRedemptionPeriod, // Expired (30 more days after grace period)
    ExpiredPendingDelete,    // Expired (5 more days on top of grace and redemption periods)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WhoIsThereError {
    /// No parser is available for the domain name's top-level domain
    UnsupportedTld,
}

impl std::fmt::Display for WhoIsThereError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WhoIsThereError::UnsupportedTld => f.write_str("unsupported top-level domain"),
        }
    }
}

impl std::error::Error for WhoIsThereError {}

/// Domain information extracted from a WHOIS response
///
/// String slices borrow from the WHOIS response that was parsed.
/// Fields are `None` when the response didn't contain that information.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DomainProps<'t> {
    /// Domain name as spelled in the response (registries differ in letter case);
    /// empty if the response doesn't include it
    pub name: &'t str,
    pub whois_service: Option<WhoisService>,
    pub is_registered: Option<bool>,
    /// RFC 3339 timestamp in UTC, e.g. `2024-04-21T23:59:59+00:00`
    pub expiry_date: Option<String>,
    pub registrar: Option<&'t str>,
    pub status: Option<DomainStatus>,
}

/// Parses a raw WHOIS response for `domain_name`
///
/// The response format is picked from the domain name's top-level domain,
/// matched case-insensitively (a trailing dot is allowed).
///
/// # Errors
///
/// Returns [`WhoIsThereError::UnsupportedTld`] if the TLD isn't supported.
pub fn parse_domain_whois_info<'t>(
    domain_name: &'t str,
    whois_info: &'t str,
) -> Result<DomainProps<'t>, WhoIsThereError> {
    // Accept fully-qualified names ("example.com.") and any letter case
    let tld = domain_name
        .trim_end_matches('.')
        .rsplit_once('.')
        .map(|(_, tld)| tld.to_ascii_lowercase())
        .ok_or(WhoIsThereError::UnsupportedTld)?;

    let parse = match tld.as_str() {
        "co" | "com" | "fm" | "io" | "social" => parse_icann_domain_whois_info,
        "edu" => parse_educause_domain_whois_info,
        "gov" => parse_dotgov_domain_whois_info,
        "il" => parse_isocil_domain_whois_info,
        "is" => parse_isnic_domain_whois_info,
        "it" => parse_nicit_domain_whois_info,
        "jp" => parse_jprs_domain_whois_info,
        "kr" => parse_krnic_domain_whois_info,
        "rs" => parse_rnids_domain_whois_info,
        "ru" => parse_tcinet_domain_whois_info,
        "uk" => parse_nominet_domain_whois_info,
        _ => return Err(WhoIsThereError::UnsupportedTld),
    };

    Ok(parse(whois_info))
}
