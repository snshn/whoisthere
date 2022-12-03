# whoisthere

Rust crate for parsing WHOIS domain info


---------------------------------------------------


## Usage
```rust
use whoisthere::parse_domain_whois_info;

let domain_name: &str = "somesite.co.uk";
let whois_response_file_path_string: String = format!("tests/_data_/{}.txt", &domain_name);
let whois_response_file_path: &Path = Path::new(&whois_response_file_path_string);
let whois_response: String = fs::read_to_string(whois_response_file_path.as_os_str())
    .expect("Something went wrong reading the file");
let domain_info = parse_domain_whois_info(domain_name, &whois_response);

assert_eq!(domain_info.domain_name, "somesite.co.uk");
assert_eq!(domain_info.expiration_date, Some("2022-05-14T00:00:00Z"));
assert_eq!(domain_info.registrar, Some("Paragon Internet Group Ltd t/a Tsohost [Tag = UKWEBHOSTING]"));
assert_eq!(domain_info.is_registered, Some(true));
```


---------------------------------------------------


## License

To the extent possible under law, the author(s) have dedicated all copyright related and neighboring rights to this software to the public domain worldwide.
This software is distributed without any warranty.
