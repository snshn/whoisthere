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

    use whoisthere::DomainPropStatus;

    #[test]
    fn crates_io() {
        let domain_name = "crates.io";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "crates.io");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2023-01-22T08:28:29+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("Gandi SAS"));
        // assert_eq!(domain_props.status, DomainPropStatus::Registered);
    }

    #[test]
    fn ferrari_it() {
        let domain_name = "ferrari.it";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "ferrari.it");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2023-04-15T00:00:00+00:00".to_string())
        );
        // assert_eq!(domain_props.registrar, Some("BARBERO-REG"));
        // assert_eq!(domain_props.status, DomainPropStatus::Registered);
    }

    #[test]
    fn registered_rs() {
        let domain_name = "registered.rs";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "registered.rs");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2023-03-24T19:25:04+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("NINET Company d.o.o."));
        // assert_eq!(domain_props.status, DomainPropStatus::Registered);
    }

    #[test]
    fn site_is() {
        let domain_name = "site.is";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "site.is");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2021-03-14T00:00:00+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, None);
        // assert_eq!(domain_props.status, DomainPropStatus::Unknown);
    }

    #[test]
    fn somesite_co_uk() {
        let domain_name: &str = "somesite.co.uk";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "somesite.co.uk");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2022-05-14T00:00:00+00:00".to_string())
        );
        // assert_eq!(
        //     domain_props.registrar,
        //     Some("Paragon Internet Group Ltd t/a Tsohost [Tag = UKWEBHOSTING]")
        // );
        // assert_eq!(domain_props.status, DomainPropStatus::Registered);
    }

    #[test]
    fn tesla_co_il() {
        let domain_name: &str = "tesla.co.il";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "tesla.co.il");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(domain_props.expiration_date, None);
        // assert_eq!(
        //     domain_props.registrar,
        //     Some("Paragon Internet Group Ltd t/a Tsohost [Tag = UKWEBHOSTING]")
        // );
        // assert_eq!(domain_props.status, DomainPropStatus::Registered);
    }

    #[test]
    fn whitehouse_gov() {
        let domain_name: &str = "whitehouse.gov";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "whitehouse.gov");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(domain_props.expiration_date, None);
    }

    #[test]
    fn yandex_ru() {
        let domain_name = "yandex.ru";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "yandex.ru");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2022-09-30T21:00:00+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("RU-CENTER-RU"));
        // assert_eq!(domain_props.status, DomainPropStatus::Registered);
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

    use whoisthere::DomainPropStatus;

    #[test]
    fn unregistered_gov() {
        let domain_name = "unregistered.gov";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "unregistered.gov");
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiration_date, None);
        // assert_eq!(domain_props.status, DomainPropStatus::Unregistered);
    }

    #[test]
    fn unregistered_social() {
        let domain_name = "unregistered.social";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "unregistered.social");
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiration_date, None);
        // assert_eq!(domain_props.status, DomainPropStatus::Unregistered);
    }

    #[test]
    fn expired_com() {
        let domain_name = "expired.com";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(&domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "expired.com");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2021-04-09T03:02:37+00:00".to_string())
        );
        // assert_eq!(domain_props.status, DomainPropStatus::GracePeriod);
    }

    #[test]
    fn unregistered_is() {
        let domain_name = "unregistered.is";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "unregistered.is");
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiration_date, None);
        // assert_eq!(domain_props.status, DomainPropStatus::Unregistered);
    }

    #[test]
    fn empty() {
        let mock_domain_name = "";
        let mock_whois_response = "";
        let domain_props = whoisthere::parse_info(mock_domain_name, mock_whois_response);

        assert_eq!(domain_props.domain_name, "");
        assert_eq!(domain_props.is_registered, None);
        assert_eq!(domain_props.expiration_date, None);
        // assert_eq!(domain_props.status, DomainPropStatus::Unknown);
    }

    #[test]
    fn unregistered_il() {
        let domain_name = "unregistered.il";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "unregistered.il");
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiration_date, None);
        // assert_eq!(domain_props.status, DomainPropStatus::Unregistered);
    }
}
