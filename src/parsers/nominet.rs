// Nominet: .uk

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

use crate::DomainProps;

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

pub fn parse_nominet_domain_whois_info<'a>(whois_info: &'a str) -> DomainProps<'a> {
    let mut domain_props = DomainProps {
        domain_name: "",
        is_registered: None,
        expiry_date: None,
        registrar: None,
    };

    let lines = whois_info.lines();
    let mut group: Group = Group::No;

    for line in lines {
        if line == "" {
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
                domain_props.domain_name = caps.get(1).unwrap().as_str();
            }
            continue;
        } else if group == Group::RelevantDates {
            if line.starts_with("        Expiry date:  ") {
                let re = Regex::new(r"\s+Expiry date:\s+(.*)").unwrap();
                for caps in re.captures_iter(line) {
                    let naive_date =
                        NaiveDate::parse_from_str(caps.get(1).unwrap().as_str(), "%d-%B-%Y")
                            .unwrap();
                    let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
                    let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
                    domain_props.expiry_date = Some(datetime_utc.to_rfc3339());
                    domain_props.is_registered = Some(true);
                }
                continue;
            }
        }
    }

    return domain_props;
}
