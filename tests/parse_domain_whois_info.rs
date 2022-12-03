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

    #[test]
    fn crates_io() {
        let domain_name = "crates.io";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "crates.io");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2023-01-22T08:28:29+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("Gandi SAS"));
    }

    #[test]
    fn ferrari_it() {
        let domain_name = "ferrari.it";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "ferrari.it");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2023-04-15T00:00:00+00:00".to_string())
        );
        // assert_eq!(domain_props.registrar, Some("BARBERO-REG"));
    }

    #[test]
    fn rustup_rs() {
        let domain_name = "rustup.rs";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "rustup.rs");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2026-01-26T18:43:08+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("Webglobe d.o.o."));
    }

    #[test]
    fn site_is() {
        let domain_name = "site.is";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "site.is");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2021-03-14T00:00:00+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, None);
    }

    #[test]
    fn somesite_co_uk() {
        let domain_name: &str = "somesite.co.uk";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

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
    }

    #[test]
    fn tesla_co_il() {
        let domain_name: &str = "tesla.co.il";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "tesla.co.il");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(domain_props.expiration_date, None);
        // assert_eq!(
        //     domain_props.registrar,
        //     Some("Paragon Internet Group Ltd t/a Tsohost [Tag = UKWEBHOSTING]")
        // );
    }

    #[test]
    fn whitehouse_gov() {
        let domain_name: &str = "whitehouse.gov";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

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
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "yandex.ru");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2022-09-30T21:00:00+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("RU-CENTER-RU"));
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

    #[test]
    fn empty() {
        let mock_domain_name = "";
        let mock_whois_response = "";
        let domain_props =
            whoisthere::parse_domain_whois_info(mock_domain_name, mock_whois_response);

        assert_eq!(domain_props.domain_name, "");
        assert_eq!(domain_props.is_registered, None);
        assert_eq!(domain_props.expiration_date, None);
    }

    #[test]
    fn expired_com() {
        let domain_name = "expired.com";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(&domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "expired.com");
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiration_date,
            Some("2021-04-09T03:02:37+00:00".to_string())
        );
    }

    #[test]
    fn unregistered_gov() {
        let domain_name = "unregistered.gov";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "unregistered.gov");
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiration_date, None);
    }

    #[test]
    fn unregistered_il() {
        let domain_name = "unregistered.il";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "unregistered.il");
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiration_date, None);
    }

    #[test]
    fn unregistered_is() {
        let domain_name = "unregistered.is";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "unregistered.is");
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiration_date, None);
    }

    #[test]
    fn unregistered_rs() {
        let domain_name = "unregistered.rs";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "unregistered.rs");
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiration_date, None);
    }

    #[test]
    fn unregistered_social() {
        let domain_name = "unregistered.social";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "unregistered.social");
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiration_date, None);
    }
}
