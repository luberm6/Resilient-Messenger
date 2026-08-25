use core_api::{
    ApiError, Backend, MembershipOperation, UploadedEvent, membership_operation_payload,
};
use ed25519_dalek::Signer;
use messenger_identity::{
    account_id, auth_challenge_payload, create_account, refresh_proof_payload,
};
use sqlx::postgres::{PgListener, PgPoolOptions};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; CI runs this test against a clean PostgreSQL service"]
async fn authentication_identity_delivery_and_migrations() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .unwrap();
    let backend = Backend::new(pool.clone());
    backend.migrate().await.unwrap();
    backend.migrate().await.unwrap();
    sqlx::query("TRUNCATE abuse_counters,blocked_accounts,push_tokens,relay_endpoints,relay_directory_versions,message_receipts,device_global_cursors,device_group_cursors,welcome_mailbox,group_events,membership_operations,group_members,groups,key_packages,refresh_sessions,access_sessions,auth_challenges,username_cooldowns,usernames,device_certificates,devices,accounts RESTART IDENTITY CASCADE")
        .execute(&pool).await.unwrap();

    let (alice_root, alice_device, alice_cert) = create_account();
    let alice_id = account_id(&alice_root);
    backend
        .register_account_device(
            alice_id,
            alice_root.0.verifying_key().to_bytes(),
            &alice_cert,
        )
        .await
        .unwrap();
    assert_eq!(
        backend
            .register_account_device(
                alice_id,
                alice_root.0.verifying_key().to_bytes(),
                &alice_cert
            )
            .await,
        Err(ApiError::Replay)
    );
    assert_eq!(
        backend.claim_username(alice_id, "Alice_01").await.unwrap(),
        "alice_01"
    );

    let challenge = backend.begin_challenge(alice_cert.device_id).await.unwrap();
    let signature = alice_device
        .0
        .sign(&auth_challenge_payload(
            &challenge.challenge_id,
            &challenge.challenge,
        ))
        .to_bytes();
    let tokens = backend
        .complete_challenge(challenge.challenge_id, signature)
        .await
        .unwrap();
    assert!(matches!(
        backend
            .complete_challenge(challenge.challenge_id, signature)
            .await,
        Err(ApiError::Replay)
    ));

    let bad = backend.begin_challenge(alice_cert.device_id).await.unwrap();
    assert!(matches!(
        backend.complete_challenge(bad.challenge_id, [0; 64]).await,
        Err(ApiError::InvalidCredentials)
    ));
    sqlx::query(
        "UPDATE auth_challenges SET expires_at=now()-interval '1 second' WHERE challenge_id=$1",
    )
    .bind(bad.challenge_id.as_slice())
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        backend.complete_challenge(bad.challenge_id, [0; 64]).await,
        Err(ApiError::Expired)
    ));

    let proof = alice_device
        .0
        .sign(&refresh_proof_payload(&tokens.refresh_token))
        .to_bytes();
    assert!(matches!(
        backend
            .rotate_refresh(alice_cert.device_id, tokens.refresh_token, [0; 64])
            .await,
        Err(ApiError::InvalidCredentials)
    ));
    let rotated = backend
        .rotate_refresh(alice_cert.device_id, tokens.refresh_token, proof)
        .await
        .unwrap();
    assert_ne!(rotated.refresh_token, tokens.refresh_token);
    assert!(matches!(
        backend
            .rotate_refresh(alice_cert.device_id, tokens.refresh_token, proof)
            .await,
        Err(ApiError::TokenReuse)
    ));

    let (bob_root, bob_device, bob_cert) = create_account();
    let bob_id = account_id(&bob_root);
    backend
        .register_account_device(bob_id, bob_root.0.verifying_key().to_bytes(), &bob_cert)
        .await
        .unwrap();
    assert_eq!(
        backend.claim_username(bob_id, "ALICE_01").await,
        Err(ApiError::Conflict)
    );
    backend.release_username(alice_id).await.unwrap();
    assert_eq!(
        backend.claim_username(bob_id, "alice_01").await,
        Err(ApiError::Conflict)
    );
    let (alice_race, bob_race) = tokio::join!(
        backend.claim_username(alice_id, "race_name"),
        backend.claim_username(bob_id, "race_name")
    );
    assert_eq!(
        usize::from(alice_race.is_ok()) + usize::from(bob_race.is_ok()),
        1
    );

    let recovery = messenger_identity::create_recovery_package(&alice_root).unwrap();
    backend
        .store_recovery_package(
            alice_id,
            recovery.recovery_identifier,
            &recovery.encrypted_root,
        )
        .await
        .unwrap();
    assert_eq!(
        backend
            .fetch_recovery_package(recovery.recovery_identifier)
            .await
            .unwrap()
            .unwrap(),
        recovery.encrypted_root
    );
    let package_id = [31; 16];
    backend
        .publish_key_package(bob_cert.device_id, package_id, b"opaque OpenMLS KeyPackage")
        .await
        .unwrap();
    assert_eq!(
        backend
            .fetch_key_package(bob_cert.device_id)
            .await
            .unwrap()
            .unwrap(),
        (package_id, b"opaque OpenMLS KeyPackage".to_vec())
    );
    assert!(
        backend
            .fetch_key_package(bob_cert.device_id)
            .await
            .unwrap()
            .is_none()
    );

    let group = [40; 16];
    backend
        .create_group(group, alice_cert.device_id, alice_id)
        .await
        .unwrap();
    backend
        .add_group_member(group, bob_cert.device_id, bob_id, 0)
        .await
        .unwrap();
    backend
        .upload_welcome(
            alice_cert.device_id,
            bob_cert.device_id,
            group,
            [39; 16],
            b"opaque MLS Welcome",
        )
        .await
        .unwrap();
    assert_eq!(
        backend
            .fetch_welcomes(bob_cert.device_id, 50)
            .await
            .unwrap()
            .len(),
        1
    );
    let event = UploadedEvent {
        event_id: [41; 16],
        group_id: group,
        author_device_id: alice_cert.device_id,
        client_message_id: [42; 16],
        event_kind: 3,
        ciphertext: b"opaque MLS application data".to_vec(),
        correlation_id: None,
    };
    let mut listener = PgListener::connect_with(&pool).await.unwrap();
    listener
        .listen(core_api::EVENT_NOTIFY_CHANNEL)
        .await
        .unwrap();
    let first = backend.upload_event(&event).await.unwrap();
    let notification = tokio::time::timeout(Duration::from_secs(2), listener.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(notification.payload(), "28282828282828282828282828282828");
    assert!(!first.duplicate);
    let duplicate = backend.upload_event(&event).await.unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(first.cursor, duplicate.cursor);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM group_events")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    let synced = backend
        .sync_group(bob_cert.device_id, group, 0, 50)
        .await
        .unwrap();
    assert_eq!(synced.len(), 1);
    assert_eq!(synced[0].ciphertext, event.ciphertext);
    assert_eq!(
        backend
            .sync_global(bob_cert.device_id, 0, 50)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        backend
            .record_receipts(bob_cert.device_id, &[event.event_id], 1)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        backend
            .record_receipts(bob_cert.device_id, &[event.event_id], 1)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        backend.sync_group([99; 16], group, 0, 50).await,
        Err(ApiError::Unauthorized)
    );
    backend
        .advance_group_cursor(bob_cert.device_id, group, first.cursor)
        .await
        .unwrap();
    assert_eq!(
        backend
            .advance_group_cursor(bob_cert.device_id, group, first.cursor - 1)
            .await,
        Err(ApiError::CursorRegression)
    );

    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM group_members")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        backend
            .add_group_member([88; 16], bob_cert.device_id, bob_id, 0)
            .await
            .is_err()
    );
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM group_members")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);

    let large_group = [70; 16];
    backend
        .create_group(large_group, alice_cert.device_id, alice_id)
        .await
        .unwrap();
    backend
        .add_group_member(large_group, bob_cert.device_id, bob_id, 0)
        .await
        .unwrap();
    let mut last_device = bob_cert.device_id;
    for _ in 0..98 {
        let (root, _, cert) = create_account();
        let id = account_id(&root);
        backend
            .register_account_device(id, root.0.verifying_key().to_bytes(), &cert)
            .await
            .unwrap();
        backend
            .add_group_member(large_group, cert.device_id, id, 0)
            .await
            .unwrap();
        last_device = cert.device_id;
    }
    let large_event = UploadedEvent {
        event_id: [71; 16],
        group_id: large_group,
        author_device_id: alice_cert.device_id,
        client_message_id: [72; 16],
        event_kind: 3,
        ciphertext: b"one ciphertext for one hundred members".to_vec(),
        correlation_id: None,
    };
    backend.upload_event(&large_event).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM group_events WHERE group_id=$1")
            .bind(large_group.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM group_members WHERE group_id=$1 AND removed_at IS NULL"
        )
        .bind(large_group.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap(),
        100
    );
    assert_eq!(
        backend
            .sync_group(last_device, large_group, 0, 50)
            .await
            .unwrap()
            .len(),
        1
    );

    let correlation = [55; 16];
    let operation = membership_operation_payload(
        &correlation,
        &group,
        &alice_cert.device_id,
        &bob_cert.device_id,
        0,
        true,
    );
    let operation_signature = alice_device.0.sign(&operation).to_bytes();
    assert!(
        !backend
            .apply_membership_operation(&MembershipOperation {
                correlation_id: correlation,
                group_id: group,
                author_device_id: alice_cert.device_id,
                target_device_id: bob_cert.device_id,
                role: 0,
                remove: true,
                signature: operation_signature,
            })
            .await
            .unwrap()
    );
    assert!(
        backend
            .apply_membership_operation(&MembershipOperation {
                correlation_id: correlation,
                group_id: group,
                author_device_id: alice_cert.device_id,
                target_device_id: bob_cert.device_id,
                role: 0,
                remove: true,
                signature: operation_signature,
            })
            .await
            .unwrap()
    );
    let commit = UploadedEvent {
        event_id: [56; 16],
        group_id: group,
        author_device_id: alice_cert.device_id,
        client_message_id: [57; 16],
        event_kind: core_api::EVENT_KIND_MLS_COMMIT,
        ciphertext: b"opaque correlated MLS commit".to_vec(),
        correlation_id: Some(correlation),
    };
    backend.upload_event(&commit).await.unwrap();
    assert_eq!(
        backend.sync_group(bob_cert.device_id, group, 0, 50).await,
        Err(ApiError::Unauthorized)
    );
    let _ = bob_device;
}
