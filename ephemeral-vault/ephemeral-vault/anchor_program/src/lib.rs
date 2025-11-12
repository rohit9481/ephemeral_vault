use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("EphVau1t1111111111111111111111111111111111");

#[program]
pub mod ephemeral_vault {
    use super::*;

    pub fn create_ephemeral_vault(
        ctx: Context<CreateEphemeralVault>,
        session_duration: i64,
        approved_amount: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let clock = Clock::get()?;

        require!(session_duration > 0 && session_duration <= 86400, VaultError::InvalidDuration);
        require!(approved_amount > 0, VaultError::InvalidAmount);

        vault.parent_wallet = ctx.accounts.parent.key();
        vault.ephemeral_wallet = Pubkey::default(); // Set during delegation
        vault.session_start = clock.unix_timestamp;
        vault.session_expiry = clock.unix_timestamp + session_duration;
        vault.last_activity = clock.unix_timestamp;
        vault.is_active = true;
        vault.total_deposited = 0;
        vault.total_spent = 0;
        vault.approved_amount = approved_amount;
        vault.bump = ctx.bumps.vault;

        emit!(VaultCreated {
            parent: ctx.accounts.parent.key(),
            vault: vault.key(),
            session_expiry: vault.session_expiry,
            approved_amount,
        });

        Ok(())
    }

    pub fn approve_delegate(
        ctx: Context<ApproveDelegate>,
        ephemeral_wallet: Pubkey,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let clock = Clock::get()?;

        require!(vault.is_active, VaultError::VaultInactive);
        require!(clock.unix_timestamp < vault.session_expiry, VaultError::SessionExpired);
        require!(vault.parent_wallet == ctx.accounts.parent.key(), VaultError::Unauthorized);

        let delegation = &mut ctx.accounts.delegation;
        delegation.vault = vault.key();
        delegation.delegate = ephemeral_wallet;
        delegation.approved_at = clock.unix_timestamp;
        delegation.revoked_at = None;
        delegation.bump = ctx.bumps.delegation;

        vault.ephemeral_wallet = ephemeral_wallet;
        vault.last_activity = clock.unix_timestamp;

        emit!(DelegateApproved {
            vault: vault.key(),
            delegate: ephemeral_wallet,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    pub fn auto_deposit_for_trade(
        ctx: Context<AutoDeposit>,
        amount: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let clock = Clock::get()?;

        require!(vault.is_active, VaultError::VaultInactive);
        require!(clock.unix_timestamp < vault.session_expiry, VaultError::SessionExpired);
        require!(vault.parent_wallet == ctx.accounts.parent.key(), VaultError::Unauthorized);
        
        let max_deposit = 10_000_000; // 0.01 SOL max per deposit
        require!(amount <= max_deposit, VaultError::ExcessiveDeposit);
        require!(vault.total_deposited + amount <= 100_000_000, VaultError::DepositLimitReached);

        // Transfer SOL from parent to vault PDA
        let transfer_ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.parent.key(),
            &vault.key(),
            amount,
        );

        anchor_lang::solana_program::program::invoke(
            &transfer_ix,
            &[
                ctx.accounts.parent.to_account_info(),
                vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        vault.total_deposited += amount;
        vault.last_activity = clock.unix_timestamp;

        emit!(FundsDeposited {
            vault: vault.key(),
            amount,
            total_deposited: vault.total_deposited,
        });

        Ok(())
    }

    pub fn execute_trade(
        ctx: Context<ExecuteTrade>,
        trade_id: u64,
        fee_amount: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let delegation = &ctx.accounts.delegation;
        let clock = Clock::get()?;

        require!(vault.is_active, VaultError::VaultInactive);
        require!(clock.unix_timestamp < vault.session_expiry, VaultError::SessionExpired);
        require!(delegation.delegate == ctx.accounts.ephemeral.key(), VaultError::Unauthorized);
        require!(delegation.revoked_at.is_none(), VaultError::DelegationRevoked);
        require!(vault.ephemeral_wallet == ctx.accounts.ephemeral.key(), VaultError::InvalidDelegate);

        let available = vault.total_deposited.checked_sub(vault.total_spent)
            .ok_or(VaultError::InsufficientFunds)?;
        require!(fee_amount <= available, VaultError::InsufficientFunds);

        vault.total_spent += fee_amount;
        vault.last_activity = clock.unix_timestamp;

        emit!(TradeExecuted {
            vault: vault.key(),
            trade_id,
            fee_amount,
            remaining: vault.total_deposited - vault.total_spent,
        });

        Ok(())
    }

    pub fn revoke_access(ctx: Context<RevokeAccess>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let delegation = &mut ctx.accounts.delegation;
        let clock = Clock::get()?;

        require!(vault.parent_wallet == ctx.accounts.parent.key(), VaultError::Unauthorized);
        require!(delegation.revoked_at.is_none(), VaultError::AlreadyRevoked);

        delegation.revoked_at = Some(clock.unix_timestamp);
        vault.is_active = false;

        // Return remaining funds to parent
        let remaining = vault.total_deposited.checked_sub(vault.total_spent).unwrap_or(0);
        if remaining > 0 {
            let rent = Rent::get()?.minimum_balance(vault.to_account_info().data_len());
            let transferable = vault.to_account_info().lamports()
                .checked_sub(rent)
                .ok_or(VaultError::InsufficientFunds)?;
            
            if transferable > 0 {
                **vault.to_account_info().try_borrow_mut_lamports()? -= transferable;
                **ctx.accounts.parent.to_account_info().try_borrow_mut_lamports()? += transferable;
            }
        }

        emit!(AccessRevoked {
            vault: vault.key(),
            returned_amount: remaining,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    pub fn cleanup_vault(ctx: Context<CleanupVault>) -> Result<()> {
        let vault = &ctx.accounts.vault;
        let clock = Clock::get()?;

        require!(
            clock.unix_timestamp > vault.session_expiry || !vault.is_active,
            VaultError::SessionNotExpired
        );

        let remaining = vault.total_deposited.checked_sub(vault.total_spent).unwrap_or(0);
        let rent = Rent::get()?.minimum_balance(vault.to_account_info().data_len());
        let vault_balance = vault.to_account_info().lamports();
        
        // Calculate cleanup reward (1% or 0.001 SOL, whichever is smaller)
        let cleanup_reward = std::cmp::min(
            remaining / 100,
            1_000_000, // 0.001 SOL
        );

        let to_parent = vault_balance.checked_sub(rent).unwrap_or(0)
            .checked_sub(cleanup_reward).unwrap_or(0);

        // Transfer to parent
        if to_parent > 0 {
            **vault.to_account_info().try_borrow_mut_lamports()? -= to_parent;
            **ctx.accounts.parent.to_account_info().try_borrow_mut_lamports()? += to_parent;
        }

        // Reward cleanup caller
        if cleanup_reward > 0 {
            **vault.to_account_info().try_borrow_mut_lamports()? -= cleanup_reward;
            **ctx.accounts.cleanup_caller.to_account_info().try_borrow_mut_lamports()? += cleanup_reward;
        }

        emit!(VaultCleaned {
            vault: vault.key(),
            returned_to_parent: to_parent,
            cleanup_reward,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }
}

// Account Structures
#[derive(Accounts)]
pub struct CreateEphemeralVault<'info> {
    #[account(mut)]
    pub parent: Signer<'info>,

    #[account(
        init,
        payer = parent,
        space = 8 + EphemeralVault::INIT_SPACE,
        seeds = [b"vault", parent.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, EphemeralVault>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ApproveDelegate<'info> {
    #[account(mut)]
    pub parent: Signer<'info>,

    #[account(
        mut,
        seeds = [b"vault", parent.key().as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, EphemeralVault>,

    #[account(
        init,
        payer = parent,
        space = 8 + VaultDelegation::INIT_SPACE,
        seeds = [b"delegation", vault.key().as_ref()],
        bump
    )]
    pub delegation: Account<'info, VaultDelegation>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AutoDeposit<'info> {
    #[account(mut)]
    pub parent: Signer<'info>,

    #[account(
        mut,
        seeds = [b"vault", parent.key().as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, EphemeralVault>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExecuteTrade<'info> {
    pub ephemeral: Signer<'info>,

    #[account(
        mut,
        seeds = [b"vault", vault.parent_wallet.as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, EphemeralVault>,

    #[account(
        seeds = [b"delegation", vault.key().as_ref()],
        bump = delegation.bump,
    )]
    pub delegation: Account<'info, VaultDelegation>,
}

#[derive(Accounts)]
pub struct RevokeAccess<'info> {
    #[account(mut)]
    pub parent: Signer<'info>,

    #[account(
        mut,
        seeds = [b"vault", parent.key().as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, EphemeralVault>,

    #[account(
        mut,
        seeds = [b"delegation", vault.key().as_ref()],
        bump = delegation.bump,
    )]
    pub delegation: Account<'info, VaultDelegation>,
}

#[derive(Accounts)]
pub struct CleanupVault<'info> {
    /// CHECK: Parent wallet receiving funds
    #[account(mut)]
    pub parent: AccountInfo<'info>,

    #[account(
        mut,
        seeds = [b"vault", parent.key().as_ref()],
        bump = vault.bump,
        close = parent
    )]
    pub vault: Account<'info, EphemeralVault>,

    #[account(mut)]
    pub cleanup_caller: Signer<'info>,
}

// Account Definitions
#[account]
#[derive(InitSpace)]
pub struct EphemeralVault {
    pub parent_wallet: Pubkey,
    pub ephemeral_wallet: Pubkey,
    pub session_start: i64,
    pub session_expiry: i64,
    pub last_activity: i64,
    pub is_active: bool,
    pub total_deposited: u64,
    pub total_spent: u64,
    pub approved_amount: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct VaultDelegation {
    pub vault: Pubkey,
    pub delegate: Pubkey,
    pub approved_at: i64,
    pub revoked_at: Option<i64>,
    pub bump: u8,
}

// Events
#[event]
pub struct VaultCreated {
    pub parent: Pubkey,
    pub vault: Pubkey,
    pub session_expiry: i64,
    pub approved_amount: u64,
}

#[event]
pub struct DelegateApproved {
    pub vault: Pubkey,
    pub delegate: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct FundsDeposited {
    pub vault: Pubkey,
    pub amount: u64,
    pub total_deposited: u64,
}

#[event]
pub struct TradeExecuted {
    pub vault: Pubkey,
    pub trade_id: u64,
    pub fee_amount: u64,
    pub remaining: u64,
}

#[event]
pub struct AccessRevoked {
    pub vault: Pubkey,
    pub returned_amount: u64,
    pub timestamp: i64,
}

#[event]
pub struct VaultCleaned {
    pub vault: Pubkey,
    pub returned_to_parent: u64,
    pub cleanup_reward: u64,
    pub timestamp: i64,
}

// Errors
#[error_code]
pub enum VaultError {
    #[msg("Invalid session duration")]
    InvalidDuration,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Vault is inactive")]
    VaultInactive,
    #[msg("Session has expired")]
    SessionExpired,
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Excessive deposit amount")]
    ExcessiveDeposit,
    #[msg("Deposit limit reached")]
    DepositLimitReached,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Delegation revoked")]
    DelegationRevoked,
    #[msg("Invalid delegate")]
    InvalidDelegate,
    #[msg("Already revoked")]
    AlreadyRevoked,
    #[msg("Session not expired")]
    SessionNotExpired,
}