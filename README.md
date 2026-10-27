# whoisthere

Rust crate for parsing WHOIS domain info


---------------------------------------------------


## Usage

```rust
use whoisthere::{DomainStatus, WhoisService, parse_domain_whois_info};

// Raw response from the registry's WHOIS server (e.g. `whois example.co.uk`)
let whois_response = "
    Domain name:
        example.co.uk

    Registrar:
        Example Registrar Ltd [Tag = EXAMPLE]
        URL: https://registrar.example

    Relevant dates:
        Registered on: 14-May-1998
        Expiry date:  14-May-2030

    Registration status:
        Registered until expiry date.
";

let domain_props =
    parse_domain_whois_info("example.co.uk", whois_response).expect("unsupported TLD");

assert_eq!(domain_props.name, "example.co.uk");
assert_eq!(domain_props.whois_service, Some(WhoisService::Nominet));
assert_eq!(domain_props.is_registered, Some(true));
assert_eq!(domain_props.expiry_date.as_deref(), Some("2030-05-14T00:00:00+00:00"));
assert_eq!(domain_props.registrar, Some("Example Registrar Ltd [Tag = EXAMPLE]"));
assert_eq!(domain_props.status, Some(DomainStatus::Active));
```


## Supported TLDs

| TLD                                                                                     | WHOIS service |
|-----------------------------------------------------------------------------------------|---------------|
| `.ai`, `.ca`, `.cc`, `.co`, `.com`, `.fm`, `.io`, `.me`, `.sh`, `.social`, `.tv`, `.us` | ICANN format  |
| `.edu`                                                                                  | EDUCAUSE      |
| `.gov`                                                                                  | DOTGOV        |
| `.il`                                                                                   | ISOC-IL       |
| `.is`                                                                                   | ISNIC         |
| `.it`                                                                                   | NIC-IT        |
| `.jp`                                                                                   | JPRS          |
| `.kr`                                                                                   | KRNIC         |
| `.rs`                                                                                   | RNIDS         |
| `.ru`                                                                                   | TCINET        |
| `.uk`                                                                                   | Nominet       |

Other TLDs return `Err(WhoIsThereError::UnsupportedTld)`.


---------------------------------------------------


## License

To the extent possible under law, the author(s) have dedicated all copyright related and neighboring rights to this software to the public domain worldwide.
This software is distributed without any warranty.
