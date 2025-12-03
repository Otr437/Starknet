// X402 Payment Protocol - Starknet Implementation
// HTTP 402 Payment Required protocol adapted for Starknet
// Supports USDC micropayments, immediate settlement, and deferred batching
// Compatible with x402 standard: https://github.com/coinbase/x402

use starknet::ContractAddress;

#[starknet::interface]
trait IERC20<TContractState> {
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(ref self: TContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool;
    fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
    fn approve(ref self: TContractState, spender: ContractAddress, amount: u256) -> bool;
}

#[starknet::interface]
trait IX402Payment<TContractState> {
    fn create_payment_request(ref self: TContractState, price_usd: u256, resource: felt252, client_id: felt252) -> felt252;
    fn process_payment(ref self: TContractState, payment_id: felt252) -> bool;
    fn verify_payment_authorization(self: @TContractState, payment_id: felt252, payer: ContractAddress) -> bool;
    fn authorize_deferred_credit(ref self: TContractState, client_id: felt252, amount_usd: u256, resource: felt252) -> (felt252, felt252);
    fn commit_deferred_usage(ref self: TContractState, client_id: felt252, amount_usd: u256, resource: felt252, auth: felt252, sig: felt252) -> bool;
    fn settle_deferred_balance(ref self: TContractState, client_id: felt252) -> bool;
    fn get_deferred_balance(self: @TContractState, client_id: felt252) -> u256;
    fn get_payment_details(self: @TContractState, payment_id: felt252) -> PaymentDetails;
    fn get_payment_status(self: @TContractState, payment_id: felt252) -> u8;
    fn get_client_payments(self: @TContractState, client_id: felt252, offset: u32, limit: u32) -> Array<felt252>;
    fn get_total_payments(self: @TContractState) -> u256;
    fn get_total_volume_usd(self: @TContractState) -> u256;
    fn set_merchant_wallet(ref self: TContractState, new_wallet: ContractAddress);
    fn set_usdc_token(ref self: TContractState, usdc_address: ContractAddress);
    fn set_price_per_unit(ref self: TContractState, resource: felt252, price_usd: u256);
    fn withdraw_usdc(ref self: TContractState, amount: u256, recipient: ContractAddress);
    fn pause_contract(ref self: TContractState);
    fn unpause_contract(ref self: TContractState);
    fn transfer_ownership(ref self: TContractState, new_owner: ContractAddress);
    fn accept_ownership(ref self: TContractState);
    fn cancel_ownership_transfer(ref self: TContractState);
    fn renounce_ownership(ref self: TContractState);
    fn get_pending_owner(self: @TContractState) -> ContractAddress;
    fn get_merchant_wallet(self: @TContractState) -> ContractAddress;
    fn get_usdc_token(self: @TContractState) -> ContractAddress;
    fn get_owner(self: @TContractState) -> ContractAddress;
    fn is_paused(self: @TContractState) -> bool;
    fn get_resource_price(self: @TContractState, resource: felt252) -> u256;
}

#[derive(Drop, Copy, Serde, starknet::Store)]
struct PaymentDetails {
    payment_id: felt252,
    payer: ContractAddress,
    price_usd: u256,
    usdc_amount: u256,
    status: u8,
    payment_scheme: u8,
    resource: felt252,
    client_id: felt252,
    timestamp: u64,
    confirmed_at: u64,
    block_number: u64,
}

#[derive(Drop, Copy, Serde, starknet::Store)]
struct DeferredCredit {
    client_id: felt252,
    amount_usd: u256,
    resource: felt252,
    authorization: felt252,
    signature: felt252,
    timestamp: u64,
    settled: bool,
    settled_at: u64,
}

#[starknet::contract]
mod X402Payment {
    use super::{ContractAddress, PaymentDetails, DeferredCredit, IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::{get_caller_address, get_block_timestamp, get_block_number, get_contract_address};
    use core::poseidon::poseidon_hash_span;
    use core::array::ArrayTrait;
    use core::pedersen::pedersen;

    const USDC_DECIMALS: u256 = 1000000;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        pending_owner: ContractAddress,
        ownership_initiated_at: u64,
        merchant_wallet: ContractAddress,
        usdc_token: ContractAddress,
        paused: bool,
        secret_key: felt252,
        payments: LegacyMap<felt252, PaymentDetails>,
        payment_exists: LegacyMap<felt252, bool>,
        payment_count: u256,
        total_volume_usd: u256,
        nonce: u256,
        client_payment_ids: LegacyMap<(felt252, u32), felt252>,
        client_payment_count: LegacyMap<felt252, u32>,
        deferred_credits: LegacyMap<(felt252, u32), DeferredCredit>,
        deferred_credit_count: LegacyMap<felt252, u32>,
        deferred_balance_usd: LegacyMap<felt252, u256>,
        used_authorizations: LegacyMap<felt252, bool>,
        resource_prices: LegacyMap<felt252, u256>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        PaymentRequested: PaymentRequested,
        PaymentConfirmed: PaymentConfirmed,
        PaymentFailed: PaymentFailed,
        DeferredCreditAuthorized: DeferredCreditAuthorized,
        DeferredUsageCommitted: DeferredUsageCommitted,
        DeferredBalanceSettled: DeferredBalanceSettled,
        MerchantWalletUpdated: MerchantWalletUpdated,
        ResourcePriceSet: ResourcePriceSet,
        USDCWithdrawn: USDCWithdrawn,
        ContractPaused: ContractPaused,
        ContractUnpaused: ContractUnpaused,
        OwnershipTransferInitiated: OwnershipTransferInitiated,
        OwnershipTransferred: OwnershipTransferred,
        OwnershipTransferCancelled: OwnershipTransferCancelled,
        OwnershipRenounced: OwnershipRenounced,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentRequested {
        #[key]
        payment_id: felt252,
        #[key]
        payer: ContractAddress,
        price_usd: u256,
        resource: felt252,
        client_id: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentConfirmed {
        #[key]
        payment_id: felt252,
        payer: ContractAddress,
        usdc_amount: u256,
        block_number: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentFailed {
        #[key]
        payment_id: felt252,
        reason: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct DeferredCreditAuthorized {
        #[key]
        client_id: felt252,
        amount_usd: u256,
        authorization: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct DeferredUsageCommitted {
        #[key]
        client_id: felt252,
        authorization: felt252,
        amount_usd: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct DeferredBalanceSettled {
        #[key]
        client_id: felt252,
        total_usd: u256,
        usdc_paid: u256,
        credit_count: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct MerchantWalletUpdated {
        old_wallet: ContractAddress,
        new_wallet: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ResourcePriceSet {
        resource: felt252,
        price_usd: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct USDCWithdrawn {
        amount: u256,
        recipient: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ContractPaused {
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ContractUnpaused {
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnershipTransferInitiated {
        #[key]
        previous_owner: ContractAddress,
        #[key]
        new_owner: ContractAddress,
        initiated_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnershipTransferred {
        #[key]
        previous_owner: ContractAddress,
        #[key]
        new_owner: ContractAddress,
        completed_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnershipTransferCancelled {
        #[key]
        owner: ContractAddress,
        #[key]
        cancelled_pending_owner: ContractAddress,
        cancelled_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnershipRenounced {
        #[key]
        previous_owner: ContractAddress,
        renounced_at: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, 
        owner: ContractAddress, 
        merchant_wallet: ContractAddress,
        usdc_token: ContractAddress,
        secret_key: felt252
    ) {
        assert(!owner.is_zero(), 'Owner cannot be zero');
        assert(!merchant_wallet.is_zero(), 'Merchant wallet cannot be zero');
        assert(!usdc_token.is_zero(), 'USDC token cannot be zero');
        assert(secret_key != 0, 'Secret key required');
        
        self.owner.write(owner);
        self.pending_owner.write(starknet::contract_address_const::<0>());
        self.merchant_wallet.write(merchant_wallet);
        self.usdc_token.write(usdc_token);
        self.secret_key.write(secret_key);
        self.paused.write(false);
        self.payment_count.write(0);
        self.total_volume_usd.write(0);
        self.nonce.write(0);
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn assert_only_owner(self: @ContractState) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'Caller not owner');
            assert(!owner.is_zero(), 'Ownership renounced');
        }

        fn assert_not_paused(self: @ContractState) {
            assert(!self.paused.read(), 'Contract paused');
        }

        fn generate_payment_id(ref self: ContractState, payer: ContractAddress, price_usd: u256) -> felt252 {
            let nonce = self.nonce.read();
            self.nonce.write(nonce + 1);
            let mut data = ArrayTrait::new();
            data.append(payer.into());
            data.append(price_usd.low.into());
            data.append(price_usd.high.into());
            data.append(get_block_timestamp().into());
            data.append(nonce.low.into());
            poseidon_hash_span(data.span())
        }

        fn generate_auth_hash(self: @ContractState, client_id: felt252, amount: u256, resource: felt252, ts: u64, nonce: u256) -> felt252 {
            let mut data = ArrayTrait::new();
            data.append(client_id);
            data.append(amount.low.into());
            data.append(amount.high.into());
            data.append(resource);
            data.append(ts.into());
            data.append(nonce.low.into());
            poseidon_hash_span(data.span())
        }

        fn sign_authorization(self: @ContractState, auth: felt252) -> felt252 {
            pedersen(auth, self.secret_key.read())
        }

        fn verify_authorization_sig(self: @ContractState, auth: felt252, sig: felt252) -> bool {
            self.sign_authorization(auth) == sig
        }

        fn usd_to_usdc(self: @ContractState, usd_cents: u256) -> u256 {
            (usd_cents * USDC_DECIMALS) / 100
        }
    }

    #[abi(embed_v0)]
    impl X402PaymentImpl of super::IX402Payment<ContractState> {
        fn create_payment_request(ref self: ContractState, price_usd: u256, resource: felt252, client_id: felt252) -> felt252 {
            self.assert_not_paused();
            assert(price_usd > 0, 'Price must be positive');
            
            let payer = get_caller_address();
            let payment_id = self.generate_payment_id(payer, price_usd);
            
            let payment = PaymentDetails {
                payment_id,
                payer,
                price_usd,
                usdc_amount: 0,
                status: 0,
                payment_scheme: 0,
                resource,
                client_id,
                timestamp: get_block_timestamp(),
                confirmed_at: 0,
                block_number: 0,
            };
            
            self.payments.write(payment_id, payment);
            self.payment_exists.write(payment_id, true);
            self.payment_count.write(self.payment_count.read() + 1);
            
            let count = self.client_payment_count.read(client_id);
            self.client_payment_ids.write((client_id, count), payment_id);
            self.client_payment_count.write(client_id, count + 1);
            
            self.emit(PaymentRequested { payment_id, payer, price_usd, resource, client_id, timestamp: get_block_timestamp() });
            payment_id
        }

        fn process_payment(ref self: ContractState, payment_id: felt252) -> bool {
            self.assert_not_paused();
            assert(self.payment_exists.read(payment_id), 'Payment not found');
            
            let mut payment = self.payments.read(payment_id);
            assert(payment.status == 0, 'Payment already processed');
            
            let payer = get_caller_address();
            assert(payment.payer == payer, 'Payer mismatch');
            
            let usdc_amount = self.usd_to_usdc(payment.price_usd);
            let merchant = self.merchant_wallet.read();
            let usdc = IERC20Dispatcher { contract_address: self.usdc_token.read() };
            
            let balance_before = usdc.balance_of(merchant);
            let success = usdc.transfer_from(payer, merchant, usdc_amount);
            assert(success, 'USDC transfer failed');
            
            let balance_after = usdc.balance_of(merchant);
            assert(balance_after >= balance_before + usdc_amount, 'Balance verification failed');
            
            payment.status = 1;
            payment.usdc_amount = usdc_amount;
            payment.confirmed_at = get_block_timestamp();
            payment.block_number = get_block_number();
            self.payments.write(payment_id, payment);
            
            self.total_volume_usd.write(self.total_volume_usd.read() + payment.price_usd);
            
            self.emit(PaymentConfirmed { payment_id, payer, usdc_amount, block_number: get_block_number() });
            true
        }

        fn verify_payment_authorization(self: @ContractState, payment_id: felt252, payer: ContractAddress) -> bool {
            if !self.payment_exists.read(payment_id) { return false; }
            let payment = self.payments.read(payment_id);
            payment.payer == payer && payment.status == 1
        }

        fn authorize_deferred_credit(ref self: ContractState, client_id: felt252, amount_usd: u256, resource: felt252) -> (felt252, felt252) {
            self.assert_not_paused();
            assert(amount_usd > 0, 'Amount must be positive');
            
            let nonce = self.nonce.read();
            self.nonce.write(nonce + 1);
            let ts = get_block_timestamp();
            
            let auth = self.generate_auth_hash(client_id, amount_usd, resource, ts, nonce);
            let sig = self.sign_authorization(auth);
            
            self.emit(DeferredCreditAuthorized { client_id, amount_usd, authorization: auth, timestamp: ts });
            (auth, sig)
        }

        fn commit_deferred_usage(ref self: ContractState, client_id: felt252, amount_usd: u256, resource: felt252, auth: felt252, sig: felt252) -> bool {
            self.assert_not_paused();
            assert(!self.used_authorizations.read(auth), 'Auth already used');
            assert(self.verify_authorization_sig(auth, sig), 'Invalid signature');
            
            self.used_authorizations.write(auth, true);
            
            let count = self.deferred_credit_count.read(client_id);
            let credit = DeferredCredit {
                client_id,
                amount_usd,
                resource,
                authorization: auth,
                signature: sig,
                timestamp: get_block_timestamp(),
                settled: false,
                settled_at: 0,
            };
            
            self.deferred_credits.write((client_id, count), credit);
            self.deferred_credit_count.write(client_id, count + 1);
            
            let balance = self.deferred_balance_usd.read(client_id);
            self.deferred_balance_usd.write(client_id, balance + amount_usd);
            
            self.emit(DeferredUsageCommitted { client_id, authorization: auth, amount_usd });
            true
        }

        fn settle_deferred_balance(ref self: ContractState, client_id: felt252) -> bool {
            self.assert_not_paused();
            
            let total_usd = self.deferred_balance_usd.read(client_id);
            assert(total_usd > 0, 'No deferred balance');
            
            let payer = get_caller_address();
            let usdc_amount = self.usd_to_usdc(total_usd);
            let merchant = self.merchant_wallet.read();
            let usdc = IERC20Dispatcher { contract_address: self.usdc_token.read() };
            
            let balance_before = usdc.balance_of(merchant);
            let success = usdc.transfer_from(payer, merchant, usdc_amount);
            assert(success, 'USDC transfer failed');
            
            let balance_after = usdc.balance_of(merchant);
            assert(balance_after >= balance_before + usdc_amount, 'Balance verification failed');
            
            let credit_count = self.deferred_credit_count.read(client_id);
            let mut settled = 0;
            let mut i: u32 = 0;
            
            loop {
                if i >= credit_count { break; }
                let mut credit = self.deferred_credits.read((client_id, i));
                if !credit.settled {
                    credit.settled = true;
                    credit.settled_at = get_block_timestamp();
                    self.deferred_credits.write((client_id, i), credit);
                    settled += 1;
                }
                i += 1;
            };
            
            self.deferred_balance_usd.write(client_id, 0);
            self.total_volume_usd.write(self.total_volume_usd.read() + total_usd);
            
            self.emit(DeferredBalanceSettled { client_id, total_usd, usdc_paid: usdc_amount, credit_count: settled });
            true
        }

        fn get_deferred_balance(self: @ContractState, client_id: felt252) -> u256 {
            self.deferred_balance_usd.read(client_id)
        }

        fn get_payment_details(self: @ContractState, payment_id: felt252) -> PaymentDetails {
            assert(self.payment_exists.read(payment_id), 'Payment not found');
            self.payments.read(payment_id)
        }

        fn get_payment_status(self: @ContractState, payment_id: felt252) -> u8 {
            if !self.payment_exists.read(payment_id) { return 2; }
            self.payments.read(payment_id).status
        }

        fn get_client_payments(self: @ContractState, client_id: felt252, offset: u32, limit: u32) -> Array<felt252> {
            let total = self.client_payment_count.read(client_id);
            let mut result = ArrayTrait::new();
            let mut i = offset;
            let end = if offset + limit < total { offset + limit } else { total };
            loop {
                if i >= end { break; }
                result.append(self.client_payment_ids.read((client_id, i)));
                i += 1;
            };
            result
        }

        fn get_total_payments(self: @ContractState) -> u256 {
            self.payment_count.read()
        }

        fn get_total_volume_usd(self: @ContractState) -> u256 {
            self.total_volume_usd.read()
        }

        fn set_merchant_wallet(ref self: ContractState, new_wallet: ContractAddress) {
            self.assert_only_owner();
            assert(!new_wallet.is_zero(), 'Zero address not allowed');
            let old = self.merchant_wallet.read();
            self.merchant_wallet.write(new_wallet);
            self.emit(MerchantWalletUpdated { old_wallet: old, new_wallet });
        }

        fn set_usdc_token(ref self: ContractState, usdc_address: ContractAddress) {
            self.assert_only_owner();
            assert(!usdc_address.is_zero(), 'Zero address not allowed');
            self.usdc_token.write(usdc_address);
        }

        fn set_price_per_unit(ref self: ContractState, resource: felt252, price_usd: u256) {
            self.assert_only_owner();
            self.resource_prices.write(resource, price_usd);
            self.emit(ResourcePriceSet { resource, price_usd });
        }

        fn withdraw_usdc(ref self: ContractState, amount: u256, recipient: ContractAddress) {
            self.assert_only_owner();
            assert(!recipient.is_zero(), 'Zero address not allowed');
            let usdc = IERC20Dispatcher { contract_address: self.usdc_token.read() };
            let contract_addr = get_contract_address();
            let balance = usdc.balance_of(contract_addr);
            assert(balance >= amount, 'Insufficient balance');
            let success = usdc.transfer(recipient, amount);
            assert(success, 'Transfer failed');
            self.emit(USDCWithdrawn { amount, recipient });
        }

        fn pause_contract(ref self: ContractState) {
            self.assert_only_owner();
            assert(!self.paused.read(), 'Already paused');
            self.paused.write(true);
            self.emit(ContractPaused { timestamp: get_block_timestamp() });
        }

        fn unpause_contract(ref self: ContractState) {
            self.assert_only_owner();
            assert(self.paused.read(), 'Not paused');
            self.paused.write(false);
            self.emit(ContractUnpaused { timestamp: get_block_timestamp() });
        }

        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self.assert_only_owner();
            assert(!new_owner.is_zero(), 'Zero address not allowed');
            let current = self.owner.read();
            assert(new_owner != current, 'Already owner');
            assert(new_owner != self.pending_owner.read(), 'Already pending');
            self.pending_owner.write(new_owner);
            self.ownership_initiated_at.write(get_block_timestamp());
            self.emit(OwnershipTransferInitiated { previous_owner: current, new_owner, initiated_at: get_block_timestamp() });
        }

        fn accept_ownership(ref self: ContractState) {
            let caller = get_caller_address();
            let pending = self.pending_owner.read();
            assert(!pending.is_zero(), 'No pending owner');
            assert(caller == pending, 'Caller not pending owner');
            let previous = self.owner.read();
            self.owner.write(pending);
            self.pending_owner.write(starknet::contract_address_const::<0>());
            self.ownership_initiated_at.write(0);
            self.emit(OwnershipTransferred { previous_owner: previous, new_owner: pending, completed_at: get_block_timestamp() });
        }

        fn cancel_ownership_transfer(ref self: ContractState) {
            self.assert_only_owner();
            let pending = self.pending_owner.read();
            assert(!pending.is_zero(), 'No pending transfer');
            self.pending_owner.write(starknet::contract_address_const::<0>());
            self.ownership_initiated_at.write(0);
            self.emit(OwnershipTransferCancelled { owner: self.owner.read(), cancelled_pending_owner: pending, cancelled_at: get_block_timestamp() });
        }

        fn renounce_ownership(ref self: ContractState) {
            self.assert_only_owner();
            assert(self.pending_owner.read().is_zero(), 'Pending transfer exists');
            let previous = self.owner.read();
            self.owner.write(starknet::contract_address_const::<0>());
            self.paused.write(true);
            self.emit(OwnershipRenounced { previous_owner: previous, renounced_at: get_block_timestamp() });
        }

        fn get_pending_owner(self: @ContractState) -> ContractAddress {
            self.pending_owner.read()
        }

        fn get_merchant_wallet(self: @ContractState) -> ContractAddress {
            self.merchant_wallet.read()
        }

        fn get_usdc_token(self: @ContractState) -> ContractAddress {
            self.usdc_token.read()
        }

        fn get_owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }

        fn get_resource_price(self: @ContractState, resource: felt252) -> u256 {
            self.resource_prices.read(resource)
        }
    }
}
