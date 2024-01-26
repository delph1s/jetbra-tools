// use chrono::NaiveDate;
// use std::fmt;

// pub fn date_to_timestamp(
//     year: i32,
//     month: u32,
//     day: u32,
//     hour: u32,
//     min: u32,
//     sec: u32,
//     milli: u32,
// ) -> Result<u64, Box<dyn std::error::Error>> {
//     let date = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_milli_opt(hour, min, sec, milli);
//     let duration_since_epoch = date.signed_duration_since(NaiveDate::from_ymd_opt(1970, 1, 1).and_hms(0, 0, 0));
//     Ok(duration_since_epoch.num_seconds() as u64)
// }

/// Converts a tuple to a tm structure.
///
/// # Arguments
///
/// * `datetime` - A tuple representing the datetime.
///
/// # Returns
///
/// A Result containing a tm structure, or an error message.
// fn time_to_tm(datetime: (i32, u32, u32, u32, u32, u32)) -> Result<std::time::Tm, Box<dyn fmt::Error>> {
//     Ok(std::time::Tm {
//         tm_year: datetime.0 - 1900,    // tm_year is years since 1900
//         tm_mon: datetime.1 as i32 - 1, // tm_mon is 0-based
//         tm_mday: datetime.2 as i32,
//         tm_hour: datetime.3 as i32,
//         tm_min: datetime.4 as i32,
//         tm_sec: datetime.5 as i32,
//         ..std::time::empty_tm()
//     })
// }
