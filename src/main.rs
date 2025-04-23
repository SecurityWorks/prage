use std::env;
use std::fs::File;
use std::io::copy;

use age::{
    secrecy::SecretString,
    Decryptor, Encryptor,
};
use rpassword::read_password;
use anyhow::{Context, Result};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 || (args[1] != "enc" && args[1] != "dec") {
        eprintln!("Usage:");
        eprintln!("  prage enc <input> <output>");
        eprintln!("  prage dec <input> <output>");
        std::process::exit(1);
    }

    let command = &args[1];
    let input_path = &args[2];
    let output_path = &args[3];

    match command.as_str() {
        "enc" => encrypt_file(input_path, output_path),
        "dec" => decrypt_file(input_path, output_path),
        _ => unreachable!(),
    }
}

fn read_passphrase_twice() -> Result<SecretString> {
    println!("Enter passphrase: ");
    let pass1 = read_password()?.trim().to_string();

    println!("Confirm passphrase: ");
    let pass2 = read_password()?.trim().to_string();

    if pass1 != pass2 {
        anyhow::bail!("❌ Passphrases do not match");
    }

    Ok(SecretString::from(pass1))
}

fn read_passphrase_once() -> Result<SecretString> {
    println!("Enter passphrase: ");
    Ok(SecretString::from(read_password()?.trim().to_string()))
}

fn encrypt_file(input_path: &str, output_path: &str) -> Result<()> {
    let passphrase = read_passphrase_twice()?;
    let encryptor = Encryptor::with_user_passphrase(passphrase);

    let mut input = File::open(input_path)
        .with_context(|| format!("❌ Failed to open input file: {}", input_path))?;
    let mut output = File::create(output_path)
        .with_context(|| format!("❌ Failed to create output file: {}", output_path))?;

    let mut writer = encryptor.wrap_output(&mut output)?;
    copy(&mut input, &mut writer)?;
    writer.finish()?;

    println!("✅ File encrypted to '{}'", output_path);
    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str) -> Result<()> {
    let passphrase = read_passphrase_once()?;
    let mut input = File::open(input_path)
        .with_context(|| format!("❌ Failed to open encrypted file: {}", input_path))?;
    let mut output = File::create(output_path)
        .with_context(|| format!("❌ Failed to create output file: {}", output_path))?;

    let decryptor = Decryptor::new(&mut input)?;
    let mut reader = decryptor.decrypt(std::iter::once(&age::scrypt::Identity::new(passphrase) as _))?;
    copy(&mut reader, &mut output)?;

    println!("✅ File decrypted to '{}'", output_path);
    Ok(())
}
