// ICANN format: gTLDs (.com, .social) and ccTLDs that use it (.ai, .ca, .cc, .co, .fm, .io, .me, .sh, .tv, .us)

use super::util::{between, rfc3339_to_rfc3339, value_after};
use crate::{DomainProps, DomainStatus, WhoisService};

pub fn parse_icann_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Icann),
        ..Default::default()
    };

    for line in whois_info.lines() {
        if line.is_empty() {
            continue;
        }

        if line == "Domain not found." {
            domain_props.is_registered = Some(false);
            break;
        }

        if let Some(name) = between(line, "No match for domain \"", "\".") {
            domain_props.is_registered = Some(false);
            domain_props.name = name;
            break;
        }

        let line = line.trim();

        if let Some(expires) = value_after(line, "Registry Expiry Date:") {
            domain_props.expiry_date = rfc3339_to_rfc3339(expires);
            domain_props.is_registered = Some(true);
            continue;
        }

        if let Some(registrar) = value_after(line, "Registrar:") {
            // TODO: scan following lines, use struct { name, url }
            domain_props.registrar = Some(registrar);
            continue;
        }

        if let Some(name) = value_after(line, "Domain Name:") {
            domain_props.name = name;
            domain_props.is_registered = Some(true);
            continue;
        }

        if let Some(status) = value_after(line, "Domain Status:") {
            // Status values look like "redemptionPeriod https://icann.org/epp#redemptionPeriod"
            let status = match status.split_whitespace().next() {
                Some("autoRenewPeriod") => DomainStatus::ExpiredGracePeriod,
                Some("redemptionPeriod") => DomainStatus::ExpiredRedemptionPeriod,
                Some("pendingDelete") => DomainStatus::ExpiredPendingDelete,
                _ => continue,
            };
            // Registries list pendingDelete alongside redemptionPeriod during the
            // redemption grace period, so keep the most specific one
            if expiry_stage(&status) > domain_props.status.as_ref().map_or(0, expiry_stage) {
                domain_props.status = Some(status);
            }
        }
    }

    if domain_props.is_registered == Some(true) && domain_props.status.is_none() {
        domain_props.status = Some(DomainStatus::Active);
    }

    domain_props
}

fn expiry_stage(status: &DomainStatus) -> u8 {
    match status {
        DomainStatus::Active => 0,
        DomainStatus::ExpiredGracePeriod => 1,
        DomainStatus::ExpiredPendingDelete => 2,
        DomainStatus::ExpiredRedemptionPeriod => 3,
    }
}
