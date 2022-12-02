use regex::Regex;

pub fn parse_registrar(whois_info: &str) -> Option<&str> {
    let lines = whois_info.lines();

    for line in lines {
        let line_trimmed = line.trim();

        if line_trimmed.starts_with("Registrar:") || line_trimmed.starts_with("registrar:") {
            let re = Regex::new(r"(?i)Registrar:\s+(.*)").unwrap();
            // TODO: scan following lines, use struct { name, url }
            for caps in re.captures_iter(line) {
                let result = caps.get(1).unwrap().as_str();
                return Some(result);
            }
            continue;
        }
    }

    None
}
