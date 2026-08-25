use messenger_identity::{
    account_id, canonical_username, create_account, create_recovery_package,
    decode_and_verify_qr_payload, encode_qr_payload, restore_account_root, sign_invite,
};

fn main() {
    let (alice, _, _) = create_account();
    let (bob, _, _) = create_account();
    let alice_name = canonical_username("Alice_01").expect("valid exact username");
    let bob_name = canonical_username("Bob_01").expect("valid exact username");
    let alice_qr = encode_qr_payload(&alice, &sign_invite(&alice, None)).expect("Alice invite");
    let bob_qr = encode_qr_payload(&bob, &sign_invite(&bob, None)).expect("Bob invite");
    decode_and_verify_qr_payload(&alice_qr, 0).expect("Alice signed invite");
    decode_and_verify_qr_payload(&bob_qr, 0).expect("Bob signed invite");
    let recovery = create_recovery_package(&alice).expect("client-side recovery");
    let restored = restore_account_root(&recovery.phrase.to_string(), &recovery.encrypted_root)
        .expect("clean-device restore");
    assert_eq!(account_id(&alice), account_id(&restored));
    println!(
        "created {alice_name} and {bob_name}; exchanged signed invites; restored Alice without server plaintext"
    );
}
