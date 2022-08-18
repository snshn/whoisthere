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
    fn somesite_co_uk() {
        let domain_name: &str = "somesite.co.uk";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "somesite.co.uk");
        assert_eq!(domain_props.expiration_date, "2022-05-14T00:00:00Z");
        assert_eq!(domain_props.registrar, None);
        assert_eq!(domain_props.is_registered, true);
        assert_eq!(domain_props.is_under_grace_period, false);
    }

    #[test]
    fn crates_io() {
        let domain_name = "crates.io";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "crates.io");
        assert_eq!(domain_props.expiration_date, "2023-01-22T08:28:29Z");
        assert_eq!(domain_props.registrar, Some("Gandi SAS".to_string()));
        assert_eq!(domain_props.is_registered, true);
        assert_eq!(domain_props.is_under_grace_period, false);
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
        assert_eq!(domain_props.expiration_date, "2023-03-24T19:25:04Z");
        assert_eq!(
            domain_props.registrar,
            Some("NINET Company d.o.o.".to_string())
        );
        assert_eq!(domain_props.is_registered, true);
        assert_eq!(domain_props.is_under_grace_period, false);
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
        assert_eq!(domain_props.expiration_date, "2021-03-14T00:00:00Z");
        assert_eq!(domain_props.registrar, None);
        assert_eq!(domain_props.is_registered, true);
        assert_eq!(domain_props.is_under_grace_period, false);
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
        assert_eq!(domain_props.expiration_date, "2022-09-30T21:00:00Z");
        assert_eq!(domain_props.registrar, Some("RU-CENTER-RU".to_string()));
        assert_eq!(domain_props.is_registered, true);
        assert_eq!(domain_props.is_under_grace_period, false);
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
    fn unregistered_gov() {
        let domain_name = "unregistered.gov";
        let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
        let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
        let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
            .expect("Something went wrong reading the file");
        let domain_props = whoisthere::parse_info(domain_name, &whois_response);

        assert_eq!(domain_props.domain_name, "unregistered.gov");
        assert_eq!(domain_props.expiration_date, "");
        assert_eq!(domain_props.is_registered, false);
        assert_eq!(domain_props.is_under_grace_period, false);
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
        assert_eq!(domain_props.expiration_date, "");
        assert_eq!(domain_props.is_registered, false);
        assert_eq!(domain_props.is_under_grace_period, false);
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
        assert_eq!(domain_props.expiration_date, "2021-04-09T03:02:37Z");
        assert_eq!(domain_props.is_registered, true);
        assert_eq!(domain_props.is_under_grace_period, true);
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
        assert_eq!(domain_props.expiration_date, "");
        assert_eq!(domain_props.is_registered, false);
        assert_eq!(domain_props.is_under_grace_period, false);
    }

    #[test]
    fn empty() {
        let mock_domain_name = "";
        let mock_whois_response = "";
        let domain_props = whoisthere::parse_info(mock_domain_name, mock_whois_response);

        assert_eq!(domain_props.domain_name, "");
        assert_eq!(domain_props.expiration_date, "");
        assert_eq!(domain_props.is_registered, false);
        assert_eq!(domain_props.is_under_grace_period, false);
    }
}
