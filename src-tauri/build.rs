#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_wrap)]
fn main() {
    tauri_build::build();

    // Embed git commit hash at compile time.
    let hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "unknown".to_string(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        );
    println!("cargo:rustc-env=VERROU_BUILD_HASH={hash}");

    // Embed build date (YYYY-MM-DD).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or_else(
            |_| "unknown".to_string(),
            |d| {
                // Simple UTC date calculation without external crates.
                let secs = d.as_secs();
                let days = secs / 86400;
                // Days since 1970-01-01
                let mut y = 1970i64;
                let mut remaining = days as i64;
                loop {
                    let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                        366
                    } else {
                        365
                    };
                    if remaining < days_in_year {
                        break;
                    }
                    remaining -= days_in_year;
                    y += 1;
                }
                let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
                let month_days: [i64; 12] = [
                    31,
                    if leap { 29 } else { 28 },
                    31,
                    30,
                    31,
                    30,
                    31,
                    31,
                    30,
                    31,
                    30,
                    31,
                ];
                let mut m = 0usize;
                for (i, &md) in month_days.iter().enumerate() {
                    if remaining < md {
                        m = i;
                        break;
                    }
                    remaining -= md;
                }
                format!("{y}-{:02}-{:02}", m + 1, remaining + 1)
            },
        );
    println!("cargo:rustc-env=VERROU_BUILD_DATE={now}");
}
