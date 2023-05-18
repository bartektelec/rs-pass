use libaes::Cipher;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::{eprintln, io};
use std::{fs, io::Write};

use sha256::{digest, try_digest};

const WORK_FACTOR: u8 = 10;
const IV: &[u8; 16] = b"w9z$C&F)J@NcRfUj";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PasswordEntry {
    name: String,
    username: String,
    pass: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct JSONFile {
    d: Vec<PasswordEntry>,
}

fn main() {
    let filename = "./store.json";

    start(filename);
}

fn start(path: &str) {
    let file = fs::read_to_string(path);

    match file {
        Ok(v) => {
            read_file(v, path);
        }
        Err(_) => {
            println!("No file found, creating a new one.");
            create_file(path);
            start(path);
        }
    };
}

fn read_file(contents: String, path: &str) {
    let mut store: JSONFile = serde_json::from_str(&contents).unwrap();
    let mut input = String::new();

    let master_key = store
        .d
        .iter()
        .find(|entry| &entry.name == "rs-pass")
        .expect("No master key found!");

    println!("Please enter your master password:");

    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            if master_key.pass != digest(input.trim()) {
                println!("Master password wrong, try again.");
                read_file(contents, path);
            }

            let mut byte_key = [0u8; 16];

            byte_key[..input.trim().len()].copy_from_slice(input.trim().to_string().as_bytes());

            let cipher = libaes::Cipher::new_128(&byte_key);

            unlock(&mut store, &cipher, path);
        }
        Err(_) => eprintln!("Error occured when reading user input"),
    }
}

fn unlock(store: &mut JSONFile, private_key: &Cipher, path: &str) {
    let mapped_store: Vec<&PasswordEntry> = store
        .d
        .iter()
        .filter(|&entry| &entry.name != "rs-pass")
        .collect();

    println!("Here is your password list:");

    for idx in 0..mapped_store.iter().len() {
        let entry = mapped_store.iter().nth(idx).unwrap();

        let raw_bytes = entry
            .pass
            .chars()
            .collect::<Vec<char>>()
            .iter()
            .map(|c| *c as u8)
            .collect::<Vec<_>>();

        let decoded = private_key.cbc_decrypt(IV, &raw_bytes);

        println!(
            "{}: {} | {} | {}",
            idx + 1,
            entry.name,
            entry.username,
            std::str::from_utf8(&decoded).unwrap()
        );
    }

    add_entry(store, &private_key, path);
}

fn add_entry(store: &mut JSONFile, private_key: &Cipher, path: &str) {
    let taken_names: Vec<&String> = store.d.iter().map(|x| &x.name).collect();

    let mut input_name = String::new();
    let mut input_user = String::new();
    let mut input_pass = String::new();

    println!("Enter name of an entry to add: ");

    io::stdin().read_line(&mut input_name).unwrap();

    if taken_names.contains(&&input_name.trim().to_string()) {
        println!("There already is an entry called that.");
        add_entry(store, &private_key, path);
    }

    println!("Enter username for the entry:");

    io::stdin().read_line(&mut input_user).unwrap();

    println!("Enter password for the entry:");

    io::stdin().read_line(&mut input_pass).unwrap();

    let encoded_pass = private_key.cbc_encrypt(IV, input_pass.trim().to_string().as_bytes());
    let pass: String = encoded_pass.iter().map(|b| *b as char).collect();

    let new_entry = PasswordEntry {
        name: input_name.trim().to_string(),
        username: input_user.trim().to_string(),
        pass,
    };

    store.d.push(new_entry);

    let mut file = File::options().write(true).open(path).unwrap();

    write_json_file(&store, &mut file);

    unlock(store, &private_key, path);
}

fn create_file(path: &str) {
    println!("Please enter your master password you want to protect the file with:");
    let mut input = String::new();
    let mut input_repeat = String::new();

    let mut master_key = PasswordEntry {
        name: "rs-pass".to_string(),
        username: "root".to_string(),
        pass: "".to_string(),
    };

    match io::stdin().read_line(&mut input) {
        Ok(_) => {}
        Err(_) => eprintln!("Error occured when reading user input"),
    };

    println!("Please repeat the chosen password:");

    match io::stdin().read_line(&mut input_repeat) {
        Ok(_) => {
            if input != input_repeat {
                println!("Passwords don't seem to match, try again");
                create_file(path);
            }
            master_key.pass = digest(input.trim().to_string());
        }
        Err(_) => {
            eprintln!("Error occured when reading user input");
        }
    };

    let mut file = File::create(path).expect("Could not create a store file");

    let content = JSONFile {
        d: vec![master_key],
    };

    write_json_file(&content, &mut file);
}

fn write_json_file(store: &JSONFile, file: &mut File) {
    file.write_all(&serde_json::to_string(store).unwrap().into_bytes())
        .unwrap();
}
