use std::fs::File;
use std::io::{self, BufRead};
use std::collections::HashMap;
use std::path::Path;



fn main(){
    //Path to Read file
    let path = "log.txt";

    //Threat Detection
    let threats = vec![
        "SQL Injection", 
        "Failed password root", 
        "Brute Force", "Malware"];

    //Log level
    let mut log_counts = HashMap::new();


    println!("--- Mini SOC System ---");

    if let Ok  (lines) = read_lines(path){
        for line in lines.flatten(){
            let part: Vec<&str> = line.splitn(2,' ').collect();
            if part.len() >= 2{
                let level = part[0];
                let massage = part[1];
                *log_counts.entry(level.to_string()).or_insert(0) += 1 ;

            for threat in &threats{
                if massage.to_lowercase().contains(&threat.to_lowercase()){
                    println!("[Alert !] Threat Detected : {} | Log : {}", threat, line);
                }
            }
            }
        }
    
    }else {
        println!("ERROR: Can't Read Log !");
        return;
    }

    println!("\n -- Summary --");
    for (level,count) in &log_counts{
        println!("{}: {} entries", level, count);
    }

}
fn read_lines<P>(filename: P)-> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())

}

