//  ██████╗  █████╗ ███████╗███████╗██╗███╗   ██╗ ██████╗
//  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║████╗  ██║██╔════╝
//  ██████╔╝███████║███████╗███████╗██║██╔██╗ ██║██║  ███╗
//  ██╔═══╝ ██╔══██║╚════██║╚════██║██║██║╚██╗██║██║   ██║
//  ██║     ██║  ██║███████║███████║██║██║ ╚████║╚██████╔╝
//  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

use std::fs;

fn fixture(domain_name: &str) -> String {
    let path = format!("tests/_data_/{}.txt", domain_name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {}: {}", path, e))
}

mod passing {
    use super::fixture;
    use whoisthere::{DomainStatus, WhoisService};

    #[test]
    fn angel_co() {
        let domain_name = "angel.co";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "angel.co");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2024-04-21T23:59:59+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("CCI REG S.A."));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn tld_matching_ignores_case_and_trailing_dot() {
        let whois_response = fixture("github.com");
        for domain_name in ["GITHUB.COM", "github.com.", "GitHub.Com."] {
            let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
                .expect("TLD should be supported");
            assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
            assert_eq!(domain_props.name, "GITHUB.COM");
        }
    }

    #[test]
    fn wayv_ai() {
        let domain_name = "wayv.ai";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "wayv.ai");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2028-07-30T20:36:17+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("Spaceship, Inc."));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn realpix_ca() {
        let domain_name = "realpix.ca";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "realpix.ca");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2028-05-29T04:01:19+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("CENTRALNIC CANADA INC"));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn soapertv_cc() {
        let domain_name = "soapertv.cc";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "SOAPERTV.CC");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2027-06-06T08:06:18+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("Domain Locale, LLC"));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn houseoflife_me() {
        let domain_name = "houseoflife.me";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "houseoflife.me");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2027-07-14T11:40:13+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("NameCheap, Inc."));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn sherwood_sh() {
        let domain_name = "sherwood.sh";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "sherwood.sh");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2027-03-16T00:30:12+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("Name.com, Inc."));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn viraltv_tv() {
        let domain_name = "viraltv.tv";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "viraltv.tv");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2027-05-15T01:45:26+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("Tucows Domains Inc."));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn chomikuj_xxx() {
        let domain_name = "chomikuj.xxx";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "chomikuj.xxx");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2026-12-06T20:23:45+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("Marcaria International LLC"));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn centralnic_xyz_fractional_seconds() {
        // Excerpt (no Domain Name line); CentralNic writes timestamps like 23:59:59.0Z
        let domain_name = "19971003.xyz";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2026-08-28T23:59:59+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("DNSPod, Inc."));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn any_gtld_uses_icann_parser() {
        for domain_name in ["example.dhl", "example.org", "EXAMPLE.Photography."] {
            let domain_props = whoisthere::parse_domain_whois_info(domain_name, "")
                .expect("gTLD should be supported");
            assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        }
    }

    #[test]
    fn crates_io() {
        let domain_name = "crates.io";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "CRATES.IO");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2023-01-22T08:28:29+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("Gandi SAS"));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn ferrari_it() {
        let domain_name = "ferrari.it";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "ferrari.it");
        assert_eq!(domain_props.whois_service, Some(WhoisService::NicIt));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2023-04-15T00:00:00+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("BARBERO-REG"));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn fuji_jp() {
        let domain_name = "fuji.jp";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "FUJI.JP");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Jprs));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2023-03-31T00:00:00+00:00".to_string())
        );
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn github_com() {
        let domain_name = "github.com";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "GITHUB.COM");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2024-10-09T18:20:50+00:00".to_string())
        );
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn nvidia_kr() {
        let domain_name = "nvidia.kr";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "nvidia.kr");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Krnic));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2023-07-24T00:00:00+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("Gabia, Inc."));
        // assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn last_fm() {
        let domain_name = "last.fm";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "LAST.FM");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2023-03-19T23:59:59+00:00".to_string())
        );
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn mit_edu() {
        let domain_name = "mit.edu";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "MIT.EDU");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Educause));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2024-07-31T00:00:00+00:00".to_string())
        );
        // assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn redemption_period_com() {
        let domain_name = "redemption-period.com";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "REDEMPTION-PERIOD.COM");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2024-01-20T18:44:06+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("GoDaddy.com, LLC"));
        assert_eq!(
            domain_props.status,
            Some(DomainStatus::ExpiredRedemptionPeriod)
        );
    }

    #[test]
    fn rustup_rs() {
        let domain_name = "rustup.rs";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "rustup.rs");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Rnids));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2026-01-26T18:43:08+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("Webglobe d.o.o."));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn site_is() {
        let domain_name = "site.is";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "site.is");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Isnic));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2021-03-14T00:00:00+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, None);
        // assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn somesite_co_uk() {
        let domain_name = "somesite.co.uk";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "somesite.co.uk");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Nominet));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2022-05-14T00:00:00+00:00".to_string())
        );
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
        assert_eq!(
            domain_props.registrar,
            Some("Paragon Internet Group Ltd t/a Tsohost [Tag = UKWEBHOSTING]")
        );
    }

    #[test]
    fn tesla_co_il() {
        let domain_name = "tesla.co.il";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "tesla.co.il");
        assert_eq!(domain_props.whois_service, Some(WhoisService::IsocIl));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2025-02-05T00:00:00+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("LiveDNS Ltd"));
    }

    #[test]
    fn whitehouse_gov() {
        let domain_name = "whitehouse.gov";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "WHITEHOUSE.GOV");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Dotgov));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(domain_props.expiry_date, None);
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }

    #[test]
    fn yandex_ru() {
        let domain_name = "yandex.ru";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "YANDEX.RU");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Tcinet));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2022-09-30T21:00:00+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("RU-CENTER-RU"));
        assert_eq!(domain_props.status, Some(DomainStatus::Active));
    }
}

//  ███████╗ █████╗ ██╗██╗     ██╗███╗   ██╗ ██████╗
//  ██╔════╝██╔══██╗██║██║     ██║████╗  ██║██╔════╝
//  █████╗  ███████║██║██║     ██║██╔██╗ ██║██║  ███╗
//  ██╔══╝  ██╔══██║██║██║     ██║██║╚██╗██║██║   ██║
//  ██║     ██║  ██║██║███████╗██║██║ ╚████║╚██████╔╝
//  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

mod failing {
    use super::fixture;
    use whoisthere::{DomainStatus, WhoIsThereError, WhoisService};

    #[test]
    fn empty() {
        let mock_domain_name = "";
        let mock_whois_response = "";
        assert_eq!(
            whoisthere::parse_domain_whois_info(mock_domain_name, mock_whois_response).err(),
            Some(WhoIsThereError::UnsupportedTld)
        );
    }

    #[test]
    fn unsupported_tlds() {
        for domain_name in [
            "com",
            ".",
            "example.de",
            "example.com.de",
            "examplecom",
            "example.int",
            "example.mil",
            "1.in-addr.arpa",
            "example.xn--p1ai",
            "example.c0m",
        ] {
            assert_eq!(
                whoisthere::parse_domain_whois_info(domain_name, "").err(),
                Some(WhoIsThereError::UnsupportedTld),
                "{}",
                domain_name
            );
        }
    }

    #[test]
    fn error_is_std_error() {
        let error: Box<dyn std::error::Error> =
            Box::new(whoisthere::parse_domain_whois_info("example.de", "").unwrap_err());
        assert_eq!(error.to_string(), "unsupported top-level domain");
    }

    #[test]
    fn malformed_dates_do_not_panic() {
        let cases = [
            (
                "example.com",
                "Domain Name: EXAMPLE.COM\nRegistry Expiry Date: soon\n",
            ),
            (
                "example.edu",
                "Domain Name: EXAMPLE.EDU\nDomain expires: 31-Foo-2024\n",
            ),
            (
                "example.is",
                "domain: example.is\nexpires: Smarch 14 2021\n",
            ),
            (
                "example.it",
                "Domain: example.it\nExpire Date: 2023-13-45\n",
            ),
            (
                "example.jp",
                "[Domain Name] EXAMPLE.JP\n[Expires on] tomorrow\n",
            ),
            (
                "example.kr",
                "Domain Name : example.kr\nExpiration Date : 2023. 07.\n",
            ),
            (
                "example.rs",
                "Domain name: example.rs\nExpiration date: 26.01.2026\n",
            ),
            ("example.ru", "domain: EXAMPLE.RU\npaid-till: 2022-09-30\n"),
            (
                "example.uk",
                "    Relevant dates:\n        Expiry date:  14-May-22x\n",
            ),
        ];
        for (domain_name, whois_response) in cases {
            let domain_props = whoisthere::parse_domain_whois_info(domain_name, whois_response)
                .expect("TLD should be supported");
            assert_eq!(domain_props.expiry_date, None, "{}", domain_name);
            assert_eq!(domain_props.is_registered, Some(true), "{}", domain_name);
        }
    }

    #[test]
    fn get_away_go_go_us() {
        // Excerpt (no Domain Name line) of a .us domain past its expiry date
        let domain_name = "get-away-go-go.us";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2026-04-25T03:33:06+00:00".to_string())
        );
        assert_eq!(domain_props.registrar, Some("GoDaddy.com, LLC"));
        assert_eq!(
            domain_props.status,
            Some(DomainStatus::ExpiredPendingDelete)
        );
    }

    #[test]
    fn expired_com() {
        let domain_name = "expired.com";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "EXPIRED.COM");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(true));
        assert_eq!(
            domain_props.expiry_date,
            Some("2021-04-09T03:02:37+00:00".to_string())
        );
        assert_eq!(
            domain_props.status,
            Some(DomainStatus::ExpiredRedemptionPeriod)
        );
    }

    #[test]
    fn unregistered_com_with_banner() {
        let whois_response = "% Registry banner\n\nNo match for domain \"UNREGISTERED.COM\".\n";
        let domain_props =
            whoisthere::parse_domain_whois_info("unregistered.com", whois_response).unwrap();
        assert_eq!(domain_props.name, "UNREGISTERED.COM");
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.status, None);
    }

    #[test]
    fn icann_expired_statuses() {
        let cases = [
            ("autoRenewPeriod", DomainStatus::ExpiredGracePeriod),
            ("redemptionPeriod", DomainStatus::ExpiredRedemptionPeriod),
            ("pendingDelete", DomainStatus::ExpiredPendingDelete),
            // During the redemption grace period both are shown
            (
                "pendingDelete https://icann.org/epp#pendingDelete\nDomain Status: redemptionPeriod",
                DomainStatus::ExpiredRedemptionPeriod,
            ),
            (
                "redemptionPeriod https://icann.org/epp#redemptionPeriod\nDomain Status: pendingDelete",
                DomainStatus::ExpiredRedemptionPeriod,
            ),
        ];
        for (status, expected) in cases {
            let whois_response = format!(
                "Domain Name: EXAMPLE.COM\nDomain Status: clientTransferProhibited\nDomain Status: {}\n",
                status
            );
            let domain_props =
                whoisthere::parse_domain_whois_info("example.com", &whois_response).unwrap();
            assert_eq!(domain_props.is_registered, Some(true), "{}", status);
            assert_eq!(domain_props.status, Some(expected), "{}", status);
        }
    }

    #[test]
    fn unregistered_edu() {
        let domain_name = "unregistered.edu";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "unregistered.edu");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Educause));
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiry_date, None);
    }

    #[test]
    fn unregistered_gov() {
        let domain_name = "unregistered.gov";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "UNREGISTERED.GOV");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Dotgov));
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiry_date, None);
    }

    #[test]
    fn unregistered_il() {
        let domain_name = "unregistered.il";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "");
        assert_eq!(domain_props.whois_service, Some(WhoisService::IsocIl));
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiry_date, None);
    }

    #[test]
    fn unregistered_is() {
        let domain_name = "unregistered.is";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "unregistered.is");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Isnic));
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiry_date, None);
        assert_eq!(domain_props.status, None);
    }

    #[test]
    fn unregistered_it() {
        let domain_name = "unregistered.it";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "unregistered.it");
        assert_eq!(domain_props.whois_service, Some(WhoisService::NicIt));
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiry_date, None);
        assert_eq!(domain_props.status, None);
    }

    #[test]
    fn unregistered_jp() {
        let domain_name = "unregistered.jp";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Jprs));
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiry_date, None);
        assert_eq!(domain_props.status, None);
    }

    #[test]
    fn unregistered_kr() {
        let domain_name = "unregistered.kr";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Krnic));
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiry_date, None);
        assert_eq!(domain_props.status, None);
    }

    #[test]
    fn unregistered_rs() {
        let domain_name = "unregistered.rs";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Rnids));
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiry_date, None);
        assert_eq!(domain_props.status, None);
    }

    #[test]
    fn unregistered_social() {
        let domain_name = "unregistered.social";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Icann));
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiry_date, None);
        assert_eq!(domain_props.status, None);
    }

    #[test]
    fn unregistered_uk() {
        let domain_name = "unregistered.uk";
        let whois_response = fixture(domain_name);
        let domain_props = whoisthere::parse_domain_whois_info(domain_name, &whois_response)
            .expect("TLD should be supported");
        assert_eq!(domain_props.name, "");
        assert_eq!(domain_props.whois_service, Some(WhoisService::Nominet));
        assert_eq!(domain_props.is_registered, Some(false));
        assert_eq!(domain_props.expiry_date, None);
        assert_eq!(domain_props.status, None);
    }
}
