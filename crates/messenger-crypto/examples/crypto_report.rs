use messenger_crypto::{CryptoEngine, MemberCredential};
use std::time::Instant;

fn member(seed: u8) -> MemberCredential {
    MemberCredential {
        device_id: [seed; 16],
        account_id: [seed; 32],
        certificate_fingerprint: [seed; 16],
    }
}

fn main() {
    println!("artifact,participants,bytes,microseconds");
    for participants in [2_usize, 10, 100] {
        let mut owner = CryptoEngine::initialize_crypto_store(member(1), [8; 32]).unwrap();
        let group_id = format!("measurement-{participants}");
        owner.create_conversation(group_id.as_bytes()).unwrap();
        let mut packages = Vec::new();
        for index in 1..participants {
            let client = CryptoEngine::initialize_crypto_store(
                member((index % 250) as u8 + 2),
                [index as u8; 32],
            )
            .unwrap();
            let started = Instant::now();
            let package = client.generate_key_packages(1).unwrap().remove(0);
            if index == 1 {
                println!(
                    "KeyPackage,{participants},{},{},",
                    package.len(),
                    started.elapsed().as_micros()
                );
            }
            packages.push(package);
        }
        let started = Instant::now();
        let change = owner
            .commit_add_members(group_id.as_bytes(), &packages)
            .unwrap();
        println!(
            "commit,{participants},{},{},",
            change.commit.len(),
            started.elapsed().as_micros()
        );
        println!(
            "Welcome,{participants},{},{},",
            change.welcome.as_ref().map_or(0, Vec::len),
            0
        );
        let started = Instant::now();
        let ciphertext = owner
            .encrypt_application_message(group_id.as_bytes(), b"OK")
            .unwrap();
        println!(
            "steady-state ciphertext,{participants},{},{},",
            ciphertext.len(),
            started.elapsed().as_micros()
        );
        let started = Instant::now();
        let state = owner
            .export_conversation_state(group_id.as_bytes())
            .unwrap();
        println!(
            "encrypted state,{participants},{},{},",
            state.len(),
            started.elapsed().as_micros()
        );
    }
}
