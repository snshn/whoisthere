//  ██████╗  █████╗ ███████╗███████╗██╗███╗   ██╗ ██████╗
//  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║████╗  ██║██╔════╝
//  ██████╔╝███████║███████╗███████╗██║██╔██╗ ██║██║  ███╗
//  ██╔═══╝ ██╔══██║╚════██║╚════██║██║██║╚██╗██║██║   ██║
//  ██║     ██║  ██║███████║███████║██║██║ ╚████║╚██████╔╝
//  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

#[cfg(test)]
mod passing {
    use std::fs;
    use std::path::Path;

    use whoisthere::WhoisService;

    #[test]
    fn angel_co() {
        let domain_name = "angel.co";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "angel.co");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2024-04-21T23:59:59+00:00".to_string())
                );
                assert_eq!(domain_props.registrar, Some("CCI REG S.A."));
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn crates_io() {
        let domain_name = "crates.io";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "CRATES.IO");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2023-01-22T08:28:29+00:00".to_string())
                );
                assert_eq!(domain_props.registrar, Some("Gandi SAS"));
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn ferrari_it() {
        let domain_name = "ferrari.it";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "ferrari.it");
                assert_eq!(domain_props.whois_service, Some(WhoisService::NicIt));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2023-04-15T00:00:00+00:00".to_string())
                );
                // assert_eq!(domain_props.registrar, Some("BARBERO-REG"));
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn fuji_jp() {
        let domain_name = "fuji.jp";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "FUJI.JP");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Jprs));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2023-03-31T00:00:00+00:00".to_string())
                );
                // assert_eq!(domain_props.registrar, Some("BARBERO-REG"));
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn github_com() {
        let domain_name = "github.com";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "GITHUB.COM");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2024-10-09T18:20:50+00:00".to_string())
                );
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn nvidia_kr() {
        let domain_name = "nvidia.kr";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "nvidia.kr");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Krnic));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2023-07-24T00:00:00+00:00".to_string())
                );
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn mit_edi() {
        let domain_name = "mit.edu";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "MIT.EDU");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Educause));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2024-07-31T00:00:00+00:00".to_string())
                );
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn rustup_rs() {
        let domain_name = "rustup.rs";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "rustup.rs");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Rnids));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2026-01-26T18:43:08+00:00".to_string())
                );
                assert_eq!(domain_props.registrar, Some("Webglobe d.o.o."));
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn site_is() {
        let domain_name = "site.is";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "site.is");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Isnic));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2021-03-14T00:00:00+00:00".to_string())
                );
                assert_eq!(domain_props.registrar, None);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn somesite_co_uk() {
        let domain_name: &str = "somesite.co.uk";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "somesite.co.uk");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Nominet));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2022-05-14T00:00:00+00:00".to_string())
                );
                // assert_eq!(
                //     domain_props.registrar,
                //     Some("Paragon Internet Group Ltd t/a Tsohost [Tag = UKWEBHOSTING]")
                // );
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn tesla_co_il() {
        let domain_name: &str = "tesla.co.il";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "tesla.co.il");
                assert_eq!(domain_props.whois_service, Some(WhoisService::IsocIl));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(domain_props.expiry_date, None);
                // assert_eq!(
                //     domain_props.registrar,
                //     Some("Paragon Internet Group Ltd t/a Tsohost [Tag = UKWEBHOSTING]")
                // );
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn whitehouse_gov() {
        let domain_name: &str = "whitehouse.gov";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "WHITEHOUSE.GOV");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Dotgov));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(domain_props.expiry_date, None);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn yandex_ru() {
        let domain_name = "yandex.ru";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "YANDEX.RU");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Tcinet));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2022-09-30T21:00:00+00:00".to_string())
                );
                assert_eq!(domain_props.registrar, Some("RU-CENTER-RU"));
            }
            Err(_) => {
                assert!(false);
            }
        }
    }
}

//  ███████╗ █████╗ ██╗██╗     ██╗███╗   ██╗ ██████╗
//  ██╔════╝██╔══██╗██║██║     ██║████╗  ██║██╔════╝
//  █████╗  ███████║██║██║     ██║██╔██╗ ██║██║  ███╗
//  ██╔══╝  ██╔══██║██║██║     ██║██║╚██╗██║██║   ██║
//  ██║     ██║  ██║██║███████╗██║██║ ╚████║╚██████╔╝
//  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

#[cfg(test)]
mod failing {
    use std::fs;
    use std::path::Path;

    use whoisthere::WhoisService;

    #[test]
    fn empty() {
        let mock_domain_name = "";
        let mock_whois_response = "";
        match whoisthere::parse_domain_whois_info(mock_domain_name, mock_whois_response) {
            Ok(_) => {
                assert!(false);
            }
            Err(_) => {
                assert!(true);
            }
        }
    }

    #[test]
    fn expired_com() {
        let domain_name = "expired.com";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(&domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "EXPIRED.COM");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
                assert_eq!(domain_props.is_registered, Some(true));
                assert_eq!(
                    domain_props.expiry_date,
                    Some("2021-04-09T03:02:37+00:00".to_string())
                );
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn unregistered_edu() {
        let domain_name = "unregistered.edu";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "unregistered.edu");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Educause));
                assert_eq!(domain_props.is_registered, Some(false));
                assert_eq!(domain_props.expiry_date, None);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn unregistered_gov() {
        let domain_name = "unregistered.gov";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "UNREGISTERED.GOV");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Dotgov));
                assert_eq!(domain_props.is_registered, Some(false));
                assert_eq!(domain_props.expiry_date, None);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn unregistered_il() {
        let domain_name = "unregistered.il";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "");
                assert_eq!(domain_props.whois_service, Some(WhoisService::IsocIl));
                assert_eq!(domain_props.is_registered, Some(false));
                assert_eq!(domain_props.expiry_date, None);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn unregistered_is() {
        let domain_name = "unregistered.is";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "unregistered.is");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Isnic));
                assert_eq!(domain_props.is_registered, Some(false));
                assert_eq!(domain_props.expiry_date, None);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn unregistered_jp() {
        let domain_name = "unregistered.jp";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Jprs));
                assert_eq!(domain_props.is_registered, Some(false));
                assert_eq!(domain_props.expiry_date, None);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn unregistered_kr() {
        let domain_name = "unregistered.kr";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Krnic));
                assert_eq!(domain_props.is_registered, Some(false));
                assert_eq!(domain_props.expiry_date, None);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn unregistered_rs() {
        let domain_name = "unregistered.rs";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Rnids));
                assert_eq!(domain_props.is_registered, Some(false));
                assert_eq!(domain_props.expiry_date, None);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn unregistered_social() {
        let domain_name = "unregistered.social";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
                assert_eq!(domain_props.is_registered, Some(false));
                assert_eq!(domain_props.expiry_date, None);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn unregistered_uk() {
        let domain_name = "unregistered.uk";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        match whoisthere::parse_domain_whois_info(domain_name, &whois_response) {
            Ok(domain_props) => {
                assert_eq!(domain_props.domain_name, "");
                assert_eq!(domain_props.whois_service, Some(WhoisService::Nominet));
                assert_eq!(domain_props.is_registered, Some(false));
                assert_eq!(domain_props.expiry_date, None);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }
}
