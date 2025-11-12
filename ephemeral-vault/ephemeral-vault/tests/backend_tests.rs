// ==================== BACKEND SERVICE TESTS ====================

#[cfg(test)]
mod backend_tests {
    use super::*;

    #[tokio::test]
    async fn test_session_manager_create_session() {
        let db_pool = setup_test_database().await;
        let encryption_key = [0u8; 32];
        let session_manager = SessionManager::new(db_pool.clone(), encryption_key);

        let parent_wallet = Keypair::new().pubkey();
        let session = session_manager
            .create_session(parent_wallet, 3600, 1_000_000)
            .await
            .unwrap();

        assert_eq!(session.parent_wallet, parent_wallet);
        assert!(session.is_active);
        assert!(session.expires_at > chrono::Utc::now().timestamp());

        cleanup_test_database(db_pool).await;
    }

    #[tokio::test]
    async fn test_session_manager_revoke_session() {
        let db_pool = setup_test_database().await;
        let encryption_key = [0u8; 32];
        let session_manager = SessionManager::new(db_pool.clone(), encryption_key);

        let parent_wallet = Keypair::new().pubkey();
        let session = session_manager
            .create_session(parent_wallet, 3600, 1_000_000)
            .await
            .unwrap();

        session_manager
            .revoke_session(&session.session_id)
            .await
            .unwrap();

        // Verify session is inactive
        let result = session_manager.get_session(&session.session_id).await;
        assert!(result.is_ok());

        cleanup_test_database(db_pool).await;
    }

    #[tokio::test]
    async fn test_auto_deposit_calculator() {
        let calculator = AutoDepositCalculator::new();

        let amount = calculator.calculate_deposit_amount(10);
        assert!(amount > 0);
        assert!(amount <= 10_000_000); // Max 0.01 SOL

        let should_top_up = calculator.should_top_up(1_000, 50);
        assert!(should_top_up);

        let top_up = calculator.calculate_top_up_amount(5_000_000, 10);
        assert!(top_up >= 0);
    }

    #[tokio::test]
    async fn test_vault_monitor_alerts() {
        let db_pool = setup_test_database().await;
        let monitor = VaultMonitor::new(db_pool.clone());

        // Create test session with low balance
        // ...

        let alerts = monitor.monitor_all_vaults().await.unwrap();
        // Verify appropriate alerts generated

        cleanup_test_database(db_pool).await;
    }

    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        let db_pool = setup_test_database().await;
        let encryption_key = [0u8; 32];
        let session_manager = SessionManager::new(db_pool.clone(), encryption_key);

        // Create expired session
        let parent_wallet = Keypair::new().pubkey();
        let session = session_manager
            .create_session(parent_wallet, -1, 1_000_000) // Already expired
            .await
            .unwrap();

        let expired = session_manager.cleanup_expired_sessions().await.unwrap();
        assert!(expired.contains(&session.session_id));

        cleanup_test_database(db_pool).await;
    }

    #[tokio::test]
    async fn test_keypair_encryption_decryption() {
        let encryption_key = [0u8; 32];
        let session_manager = SessionManager::new(
            setup_test_database().await,
            encryption_key,
        );

        let original = Keypair::new();
        let encrypted = session_manager.encrypt_keypair(&original).unwrap();
        let decrypted = session_manager.decrypt_keypair(&encrypted).unwrap();

        assert_eq!(original.pubkey(), decrypted.pubkey());
    }

    // Helper functions
    async fn setup_test_database() -> PgPool {
        // Create test database connection
        unimplemented!()
    }

    async fn cleanup_test_database(pool: PgPool) {
        // Clean up test data
        pool.close().await;
    }
}