use crate::error::Error as JBTError;
use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use std::error::Error;
use time::{Date, Month, OffsetDateTime, Time, UtcOffset};

/// `CertTime` is a struct that represents a specific date and time.
///
/// # Fields
///
/// * `year` - The year as a 32-bit integer.
/// * `month` - The month as an 8-bit unsigned integer.
/// * `day` - The day as an 8-bit unsigned integer.
/// * `hour` - The hour as an 8-bit unsigned integer.
/// * `minute` - The minute as an 8-bit unsigned integer.
/// * `second` - The second as an 8-bit unsigned integer.
/// * `microsecond` - The microsecond as a 32-bit unsigned integer.
pub struct CertTime {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub microsecond: u32,
}

/// Provides a default value for `CertTime`.
///
/// # Returns
///
/// A `CertTime` instance with the following default values:
/// * `year`: 2099
/// * `month`: 12
/// * `day`: 31
/// * `hour`: 23
/// * `minute`: 59
/// * `second`: 59
/// * `microsecond`: 999999
impl Default for CertTime {
    fn default() -> Self {
        Self {
            year: 2099,
            month: 12,
            day: 31,
            hour: 23,
            minute: 59,
            second: 59,
            microsecond: 999999,
        }
    }
}

/// Converts a `CertTime` to a Unix timestamp.
///
/// # Arguments
///
/// * `cert_time` - A `CertTime` struct containing the date and time to be converted.
///
/// # Returns
///
/// A `Result` containing a Unix timestamp (in seconds) or an error if the date or time is invalid.
pub(crate) fn datetime_to_timestamp_v1(cert_time: &CertTime) -> Result<i64, Box<dyn Error>> {
    // Attempt to create a `NaiveDate` from the year, month, and day fields of `cert_time`.
    // If the date is invalid, return an error.
    let native_date = match NaiveDate::from_ymd_opt(cert_time.year, cert_time.month as u32, cert_time.day as u32) {
        Some(date) => date,
        None => return Err(Box::new(JBTError::new("Invalid date"))),
    };

    // Attempt to create a `NaiveTime` from the hour, minute, second, and microsecond fields of `cert_time`.
    // If the time is invalid (e.g., 25:00:00), return an error.
    let native_time = match NaiveTime::from_hms_micro_opt(
        cert_time.hour as u32,
        cert_time.minute as u32,
        cert_time.second as u32,
        cert_time.microsecond,
    ) {
        Some(time) => time,
        None => return Err(Box::new(JBTError::new("Invalid time"))),
    };

    // Combine the `NaiveDate` and `NaiveTime` into a `NaiveDateTime`.
    let naive_datetime = NaiveDateTime::new(native_date, native_time);

    // Convert the `NaiveDateTime` to a `DateTime<Utc>`.
    let datetime: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive_datetime, Utc);

    // Return the Unix timestamp of the `DateTime<Utc>`.
    Ok(datetime.timestamp())
}

/// Converts a `CertTime` to a Unix timestamp.
///
/// # Arguments
///
/// * `cert_time` - A reference to a `CertTime` struct containing the date and time to be converted.
///
/// # Returns
///
/// A `Result` containing a Unix timestamp (in seconds) or an error if the date or time is invalid.
pub(crate) fn datetime_to_timestamp(cert_time: &CertTime) -> Result<i64, Box<dyn Error>> {
    // Create an OffsetDateTime object from the date and time fields of `cert_time`.
    // If any of the date or time fields are invalid, return an error.
    let dt = OffsetDateTime::new_in_offset(
        Date::from_calendar_date(cert_time.year, Month::try_from(cert_time.month)?, cert_time.day)?,
        Time::from_hms_micro(
            cert_time.hour,
            cert_time.minute,
            cert_time.second,
            cert_time.microsecond,
        )?,
        UtcOffset::from_hms(0, 0, 0)?,
    );

    // Return the Unix timestamp of the OffsetDateTime object.
    Ok(dt.unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datetime_to_timestamp_v1() {
        let cert_time = CertTime {
            year: 2008,
            month: 8,
            day: 8,
            hour: 8,
            minute: 8,
            second: 8,
            microsecond: 888888,
            ..Default::default()
        };

        assert_eq!(datetime_to_timestamp_v1(&cert_time).unwrap(), 1218182888);
    }

    #[test]
    fn test_datetime_to_timestamp() {
        let cert_time = CertTime {
            year: 2008,
            month: 8,
            day: 8,
            hour: 8,
            minute: 8,
            second: 8,
            microsecond: 888888,
            ..Default::default()
        };

        assert_eq!(datetime_to_timestamp(&cert_time).unwrap(), 1218182888);
    }
}
