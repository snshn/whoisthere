// Helpers shared by the WHOIS parsers

use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};

/// Returns the trimmed text following `prefix`, if `line` starts with it and that text isn't empty.
///
/// `value_after("Domain Name:   EXAMPLE.COM", "Domain Name:") == Some("EXAMPLE.COM")`
pub fn value_after<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let value = line.strip_prefix(prefix)?.trim();
    (!value.is_empty()).then_some(value)
}

/// Like [`value_after`], but for column-aligned lines where padding goes between the key and the colon.
///
/// `padded_value("Domain Name     : example.kr", "Domain Name") == Some("example.kr")`
pub fn padded_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    value_after(line.strip_prefix(key)?.trim_start(), ":")
}

/// Returns the text between `prefix` and `suffix`, if `line` is wrapped in both.
///
/// `between(r#"No match for "EXAMPLE.GOV"."#, "No match for \"", "\".") == Some("EXAMPLE.GOV")`
pub fn between<'a>(line: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    line.strip_prefix(prefix)?.strip_suffix(suffix)
}

/// Parses a date (no time of day) as midnight UTC, formatted as RFC 3339.
pub fn date_to_rfc3339(value: &str, format: &str) -> Option<String> {
    NaiveDate::parse_from_str(value, format)
        .ok()
        .map(|date| date.and_time(NaiveTime::MIN).and_utc().to_rfc3339())
}

/// Parses a date and time without an offset as UTC, formatted as RFC 3339.
pub fn datetime_to_rfc3339(value: &str, format: &str) -> Option<String> {
    NaiveDateTime::parse_from_str(value, format)
        .ok()
        .map(|datetime| datetime.and_utc().to_rfc3339())
}

/// Normalizes an RFC 3339 / ISO 8601 timestamp (e.g. `2021-04-09T03:02:37Z`) to UTC.
pub fn rfc3339_to_rfc3339(value: &str) -> Option<String> {
    value
        .parse::<DateTime<Utc>>()
        .ok()
        .map(|datetime| datetime.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_after_requires_non_empty_value() {
        assert_eq!(
            value_after("Registrar: Foo Inc. ", "Registrar:"),
            Some("Foo Inc.")
        );
        assert_eq!(value_after("Registrar:", "Registrar:"), None);
        assert_eq!(value_after("Registrar:   ", "Registrar:"), None);
        assert_eq!(value_after("Registrar URL: x", "Registrar:"), None);
    }

    #[test]
    fn padded_value_skips_padding() {
        assert_eq!(
            padded_value("Domain Name   : a.kr", "Domain Name"),
            Some("a.kr")
        );
        assert_eq!(padded_value("Domain Name Server : x", "Domain Name"), None);
    }

    #[test]
    fn malformed_dates_are_none() {
        assert_eq!(date_to_rfc3339("not a date", "%Y-%m-%d"), None);
        assert_eq!(
            datetime_to_rfc3339("31.02.2020 00:00:00", "%d.%m.%Y %H:%M:%S"),
            None
        );
        assert_eq!(rfc3339_to_rfc3339("yesterday"), None);
    }

    #[test]
    fn dates_are_normalized_to_utc() {
        assert_eq!(
            date_to_rfc3339("2023-04-15", "%Y-%m-%d"),
            Some("2023-04-15T00:00:00+00:00".to_string())
        );
        assert_eq!(
            rfc3339_to_rfc3339("2022-10-01T00:00:00+03:00"),
            Some("2022-09-30T21:00:00+00:00".to_string())
        );
    }
}
