pub fn parse_is_not_registered(whois_info: &str) -> bool {
    let lines = whois_info.lines();

    for line in lines {
        let line_trimmed = line.trim();

        // Parse expiration date
        if line_trimmed.starts_with("Domain not found.")
            || line_trimmed.starts_with("Domain not registered.")
            || line_trimmed.starts_with("No match for")
            || line_trimmed.starts_with("% No entries found for query")
        {
            // Nothing to do, get out of the loop
            return true;
        }
    }

    false
}
