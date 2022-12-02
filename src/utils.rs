use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;

pub fn str_to_utc_datetime(datetime: &str) -> Option<String> {
    let re_bdy = Regex::new(r"(January|February|March|April|May|June|July|August|September|October|November|December) \d{2} \d{4}").unwrap();
    let re_dby = Regex::new(r"\d{2}-(January|February|March|April|May|June|July|August|September|October|November|December)-\d{4}").unwrap();

    if re_bdy.is_match(datetime) {
        let naive_date = NaiveDate::parse_from_str(datetime, "%B %d %Y").unwrap();
        let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
        let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
        return Some(datetime_utc.to_rfc3339());
    } else if re_dby.is_match(datetime) {
        let naive_date = NaiveDate::parse_from_str(datetime, "%d-%B-%Y").unwrap();
        let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
        let datetime_utc = DateTime::<Utc>::from_utc(naive_datetime, Utc);
        return Some(datetime_utc.to_rfc3339());
    }

    None
}
