use colored::*;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::Path;

// --- 1. Struct & Config ---

struct SocEngine {
    log_file: String,
    threat_keywords: Vec<String>,
}

impl SocEngine {
    // New Instance
    fn new(log_file: &str, threats: Vec<&str>) -> Self {
        SocEngine {
            log_file: log_file.to_string(),
            threat_keywords: threats.iter().map(|&s| s.to_string()).collect(),
        }
    }

    // Helper for read file
    fn read_logs(&self) -> Vec<String> {
        let mut logs = Vec::new();
        if let Ok(file) = File::open(&self.log_file) {
            let reader = io::BufReader::new(file);
            for line in reader.lines().flatten() {
                logs.push(line);
            }
        } else {
            println!("{} Cannot open file: {}", "❌ Error:".red(), self.log_file);
        }
        logs
    }

    // --- 2. Core Functions ---

    fn analyze_logs(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        let logs = self.read_logs();

        for line in logs {
            // Edge Case
            if line.trim().is_empty() { continue; }
            
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            let level = if parts.is_empty() { "UNKNOWN" } else { parts[0] };
            
            *counts.entry(level.to_string()).or_insert(0) += 1;
        }
        counts
    }

    fn detect_threats(&self) -> Vec<String> {
        let mut detected = Vec::new();
        let logs = self.read_logs();

        for line in logs {
            let line_lower = line.to_lowercase();
            for threat in &self.threat_keywords {
                // Edge Case: Case-insensitive matching
                if line_lower.contains(&threat.to_lowercase()) {
                    detected.push(format!("[ALERT] {} | {}", threat, line));
                }
            }
        }
        detected
    }

    fn generate_report(&self) {
        let counts = self.analyze_logs();
        let threats = self.detect_threats();
        let report_file = "soc_report.txt";

        // Write to file
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(report_file)
            .expect("Cannot create report file");

        writeln!(file, "--- SOC SECURITY REPORT ---").unwrap();
        writeln!(file, "\n[Log Summary]").unwrap();
        for (level, count) in &counts {
            writeln!(file, "{}: {}", level, count).unwrap();
        }

        writeln!(file, "\n[Threats Detected: {}]", threats.len()).unwrap();
        for t in threats {
            writeln!(file, "- {}", t).unwrap();
        }

        println!("{} Saved to {}", "✅ Report Generated successfully!".green(), report_file);
    }
}

// --- 3. UI & Menu Loop ---

fn main() {
    let threats = vec!["SQL Injection", "Failed password root", "brute force", "malware"];
    let engine = SocEngine::new("logs.txt", threats);

    loop {
        println!("\n{}", "=== 🛡️  Mini SOC Dashboard ===".cyan().bold());
        println!("1. Analyze Logs");
        println!("2. Detect Threats");
        println!("3. Generate Report");
        println!("4. Exit");
        print!("Select an option: ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => {
                println!("\n{}", "--- 📊 Log Analysis ---".yellow());
                let counts = engine.analyze_logs();
                for (level, count) in counts {
                    let colored_level = match level.as_str() {
                        "INFO" => level.green(),
                        "WARN" => level.yellow(),
                        "ERROR" => level.red(),
                        _ => level.normal(),
                    };
                    println!("{}: {} entries", colored_level, count);
                }
            }
            "2" => {
                println!("\n{}", "--- 🚨 Threat Detection ---".red());
                let threats = engine.detect_threats();
                if threats.is_empty() {
                    println!("{}", "✅ No threats detected.".green());
                } else {
                    for t in threats {
                        println!("{}", t.red());
                    }
                }
            }
            "3" => {
                println!("\n{}", "--- 📄 Generating Report ---".blue());
                engine.generate_report();
            }
            "4" => {
                println!("{}", "Exiting Mini SOC. Stay secure! 🔒".cyan());
                break;
            }
            _ => println!("{}", "❌ Invalid option, please try again.".red()),
        }
    }
}
