use chrono::NaiveDate;

pub fn date_to_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
    milli: u32,
) -> Result<u64, Box<dyn std::error::Error>> {
    let date = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_milli_opt(hour, min, sec, milli);
    let duration_since_epoch = date.signed_duration_since(NaiveDate::from_ymd_opt(1970, 1, 1).and_hms(0, 0, 0));
    Ok(duration_since_epoch.num_seconds() as u64)
}
