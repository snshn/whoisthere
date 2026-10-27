// Nominet: .uk

use super::util::{date_to_rfc3339, value_after};
use crate::{DomainProps, DomainStatus, WhoisService};

#[derive(PartialEq)]
enum Group {
    No,
    DomainName,
    DataValidation,
    Registrar,
    RelevantDates,
    RegistrationStatus,
    NameServers,
}

pub fn parse_nominet_domain_whois_info(whois_info: &str) -> DomainProps<'_> {
    let mut domain_props = DomainProps {
        whois_service: Some(WhoisService::Nominet),
        ..Default::default()
    };

    let mut group: Group = Group::No;

    for line in whois_info.lines() {
        if line.is_empty() {
            group = Group::No;
            continue;
        }

        if line == "    This domain name has not been registered." {
            domain_props.is_registered = Some(false);
            break;
        }

        let next_group = match line {
            "    Domain name:" => Some(Group::DomainName),
            "    Data validation:" => Some(Group::DataValidation),
            "    Registrar:" => Some(Group::Registrar),
            "    Relevant dates:" => Some(Group::RelevantDates),
            "    Registration status:" => Some(Group::RegistrationStatus),
            "    Name servers:" => Some(Group::NameServers),
            _ => None,
        };
        if let Some(next_group) = next_group {
            group = next_group;
            continue;
        }

        let line = line.trim();

        match group {
            Group::DomainName => {
                domain_props.name = line;
            }
            Group::Registrar if domain_props.registrar.is_none() => {
                domain_props.registrar = Some(line);
            }
            Group::RelevantDates => {
                if let Some(expires) = value_after(line, "Expiry date:") {
                    domain_props.expiry_date = date_to_rfc3339(expires, "%d-%B-%Y");
                    domain_props.is_registered = Some(true);
                }
            }
            Group::RegistrationStatus if line == "Registered until expiry date." => {
                domain_props.status = Some(DomainStatus::Active);
            }
            _ => {}
        }
    }

    domain_props
}
