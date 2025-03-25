// Nominet: .uk

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

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

    let lines = whois_info.lines();
    let mut group: Group = Group::No;

    for line in lines {
        if line.is_empty() {
            group = Group::No;
            continue;
        }

        if line == "    This domain name has not been registered." {
            domain_props.is_registered = Some(false);
            break;
        }

        if line == "    Domain name:" {
            group = Group::DomainName;
            continue;
        } else if line == "    Data validation:" {
            group = Group::DataValidation;
            continue;
        } else if line == "    Registrar:" {
            group = Group::Registrar;
            continue;
        } else if line == "    Relevant dates:" {
            group = Group::RelevantDates;
            continue;
        } else if line == "    Registration status:" {
            group = Group::RegistrationStatus;
            continue;
        } else if line == "    Name servers:" {
            group = Group::NameServers;
            continue;
        }

        if group == Group::DomainName {
            // Parse domain name
            let re = Regex::new(r"\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                domain_props.name = caps.get(1).unwrap().as_str();
            }
            continue;
        } else if group == Group::RelevantDates && line.starts_with("        Expiry date:  ") {
            let re = Regex::new(r"\s+Expiry date:\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                let naive_date =
                    NaiveDate::parse_from_str(caps.get(1).unwrap().as_str(), "%d-%B-%Y").unwrap();
                let naive_datetime: NaiveDateTime = naive_date.and_hms_opt(0, 0, 0).unwrap();
                let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                domain_props.expiry_date = Some(datetime_utc.to_rfc3339());
                domain_props.is_registered = Some(true);
            }
            continue;
        } else if group == Group::RegistrationStatus {
            // Parse domain status
            let re = Regex::new(r"\s+(.*)").unwrap();
            for caps in re.captures_iter(line) {
                if caps.get(1).unwrap().as_str() == "Registered until expiry date." {
                    domain_props.status = Some(DomainStatus::Active);
                }
            }
            continue;
        }
    }

    domain_props
}
