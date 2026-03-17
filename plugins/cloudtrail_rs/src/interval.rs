// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use regex::Regex;

const RFC3339_SIMPLE: &str = "%Y-%m-%dT%H:%M:%SZ";

fn parse_endpoint(endpoint: &str) -> Result<chrono::DateTime<Utc>> {
    let duration_re = Regex::new(r"^(\d+)([wdhms])$")?;

    if let Some(caps) = duration_re.captures(endpoint) {
        let amount: i64 = caps[1].parse()?;
        let duration = match &caps[2] {
            "w" => Duration::weeks(amount),
            "d" => Duration::days(amount),
            "h" => Duration::hours(amount),
            "m" => Duration::minutes(amount),
            "s" => Duration::seconds(amount),
            _ => return Err(anyhow!("invalid duration unit")),
        };
        Ok(Utc::now() - duration)
    } else {
        let dt = chrono::NaiveDateTime::parse_from_str(endpoint, RFC3339_SIMPLE)
            .map_err(|e| anyhow!("failed to parse time '{}': {}", endpoint, e))?;
        Ok(dt.and_utc())
    }
}

/// Parse an interval string into start and end times.
/// The end time will be None if no end interval was supplied.
pub fn parse_interval(
    interval: &str,
) -> Result<(
    Option<chrono::DateTime<Utc>>,
    Option<chrono::DateTime<Utc>>,
)> {
    if interval.is_empty() {
        return Ok((None, None));
    }

    let interval_re =
        Regex::new(r"(.*)\s*-\s*(\d+[wdhms]|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$")?;

    if let Some(caps) = interval_re.captures(interval) {
        let start = parse_endpoint(caps[1].trim())?;
        let end = parse_endpoint(&caps[2])?;
        Ok((Some(start), Some(end)))
    } else {
        let start = parse_endpoint(interval)?;
        Ok((Some(start), None))
    }
}
