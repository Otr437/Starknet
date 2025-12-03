// SPDX-License-Identifier: MIT
// Privacy-Enhanced ERC20 Token for Ztarknet

#[starknet::contract]
mod PrivacyToken {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess, Map};

    #[storage]
    struct Storage {
        name: felt252,
        symbol: felt252,
        decimals: u8,
        total_supply: u256,
        // Public balances
        balances: Map<ContractAddress, u256>,
        allowances: Map<(ContractAddress, ContractAddress), u256>,
        // Shielded balances (commitment => encrypted balance)
        shielded_balances: Map<felt252, felt252>,
        // Nullifiers for spent notes
        nullifiers: Map<felt252, bool>,
        // Privacy stats
        total_shielded: u256,
        privacy_enabled: bool,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Transfer: Transfer,
        Approval: Approval,
        Shield: Shield,
        Unshield: Unshield,
        PrivateTransfer: PrivateTransfer,
    }

    #[derive(Drop, starknet::Event)]
    struct Transfer {
        #[key]
        from: ContractAddress,
        #[key]
        to: ContractAddress,
        value: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Approval {
        #[key]
        owner: ContractAddress,
        #[key]
        spender: ContractAddress,
        value: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Shield {
        #[key]
        from: ContractAddress,
        commitment: felt252,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Unshield {
        #[key]
        to: ContractAddress,
        nullifier: felt252,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct PrivateTransfer {
        input_nullifiers: Span<felt252>,
        output_commitments: Span<felt252>,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        name: felt252,
        symbol: felt252,
        decimals: u8,
        initial_supply: u256,
        recipient: ContractAddress,
        privacy_enabled: bool,
    ) {
        self.name.write(name);
        self.symbol.write(symbol);
        self.decimals.write(decimals);
        self.total_supply.write(initial_supply);
        self.balances.write(recipient, initial_supply);
        self.privacy_enabled.write(privacy_enabled);

        self.emit(Transfer {
            from: Zeroable::zero(),
            to: recipient,
            value: initial_supply
        });
    }

    #[abi(embed_v0)]
    impl PrivacyTokenImpl of super::IPrivacyToken<ContractState> {
        // Standard ERC20 functions
        fn name(self: @ContractState) -> felt252 {
            self.name.read()
        }

        fn symbol(self: @ContractState) -> felt252 {
            self.symbol.read()
        }

        fn decimals(self: @ContractState) -> u8 {
            self.decimals.read()
        }

        fn total_supply(self: @ContractState) -> u256 {
            self.total_supply.read()
        }

        fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
            self.balances.read(account)
        }

        fn allowance(
            self: @ContractState,
            owner: ContractAddress,
            spender: ContractAddress
        ) -> u256 {
            self.allowances.read((owner, spender))
        }

        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            let sender = get_caller_address();
            self._transfer(sender, recipient, amount);
            true
        }

        fn transfer_from(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256
        ) -> bool {
            let caller = get_caller_address();
            let current_allowance = self.allowances.read((sender, caller));
            
            assert(current_allowance >= amount, 'Insufficient allowance');
            
            self.allowances.write((sender, caller), current_allowance - amount);
            self._transfer(sender, recipient, amount);
            true
        }

        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
            let owner = get_caller_address();
            self.allowances.write((owner, spender), amount);
            self.emit(Approval { owner, spender, value: amount });
            true
        }

        // Privacy functions
        
        /// Shield tokens into privacy pool
        fn shield_tokens(
            ref self: ContractState,
            amount: u256,
            commitment: felt252,
            encrypted_amount: felt252,
        ) {
            assert(self.privacy_enabled.read(), 'Privacy not enabled');
            
            let caller = get_caller_address();
            let balance = self.balances.read(caller);
            assert(balance >= amount, 'Insufficient balance');

            // Deduct from public balance
            self.balances.write(caller, balance - amount);

            // Add to shielded pool
            self.shielded_balances.write(commitment, encrypted_amount);
            
            let total_shielded = self.total_shielded.read();
            self.total_shielded.write(total_shielded + amount);

            self.emit(Shield { from: caller, commitment, amount });
        }

        /// Unshield tokens from privacy pool
        fn unshield_tokens(
            ref self: ContractState,
            nullifier: felt252,
            amount: u256,
            proof: Span<felt252>,
        ) {
            assert(self.privacy_enabled.read(), 'Privacy not enabled');
            assert(!self.nullifiers.read(nullifier), 'Nullifier spent');

            // Verify proof (simplified)
            assert(proof.len() > 0, 'Invalid proof');

            let caller = get_caller_address();
            
            // Mark nullifier as spent
            self.nullifiers.write(nullifier, true);

            // Add to public balance
            let balance = self.balances.read(caller);
            self.balances.write(caller, balance + amount);

            let total_shielded = self.total_shielded.read();
            self.total_shielded.write(total_shielded - amount);

            self.emit(Unshield { to: caller, nullifier, amount });
        }

        /// Private transfer between shielded addresses
        fn private_transfer(
            ref self: ContractState,
            input_nullifiers: Span<felt252>,
            output_commitments: Span<felt252>,
            encrypted_outputs: Span<felt252>,
            proof: Span<felt252>,
        ) {
            assert(self.privacy_enabled.read(), 'Privacy not enabled');

            // Verify nullifiers unspent
            let mut i: u32 = 0;
            loop {
                if i >= input_nullifiers.len() {
                    break;
                }
                let nullifier = *input_nullifiers.at(i);
                assert(!self.nullifiers.read(nullifier), 'Nullifier spent');
                self.nullifiers.write(nullifier, true);
                i += 1;
            };

            // Verify proof
            assert(proof.len() > 0, 'Invalid proof');

            // Add new commitments
            let mut j: u32 = 0;
            loop {
                if j >= output_commitments.len() {
                    break;
                }
                let commitment = *output_commitments.at(j);
                let encrypted = *encrypted_outputs.at(j);
                self.shielded_balances.write(commitment, encrypted);
                j += 1;
            };

            self.emit(PrivateTransfer {
                input_nullifiers,
                output_commitments,
            });
        }

        /// Get total shielded value
        fn get_total_shielded(self: @ContractState) -> u256 {
            self.total_shielded.read()
        }

        /// Check if privacy is enabled
        fn is_privacy_enabled(self: @ContractState) -> bool {
            self.privacy_enabled.read()
        }

        /// Check if nullifier is spent
        fn is_nullifier_spent(self: @ContractState, nullifier: felt252) -> bool {
            self.nullifiers.read(nullifier)
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _transfer(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256
        ) {
            assert(!sender.is_zero(), 'Transfer from zero');
            assert(!recipient.is_zero(), 'Transfer to zero');

            let sender_balance = self.balances.read(sender);
            assert(sender_balance >= amount, 'Insufficient balance');

            self.balances.write(sender, sender_balance - amount);
            let recipient_balance = self.balances.read(recipient);
            self.balances.write(recipient, recipient_balance + amount);

            self.emit(Transfer { from: sender, to: recipient, value: amount });
        }
    }
}

#[starknet::interface]
trait IPrivacyToken<TContractState> {
    // Standard ERC20
    fn name(self: @TContractState) -> felt252;
    fn symbol(self: @TContractState) -> felt252;
    fn decimals(self: @TContractState) -> u8;
    fn total_supply(self: @TContractState) -> u256;
    fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
    fn allowance(self: @TContractState, owner: ContractAddress, spender: ContractAddress) -> u256;
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(
        ref self: TContractState,
        sender: ContractAddress,
        recipient: ContractAddress,
        amount: u256
    ) -> bool;
    fn approve(ref self: TContractState, spender: ContractAddress, amount: u256) -> bool;
    
    // Privacy features
    fn shield_tokens(
        ref self: TContractState,
        amount: u256,
        commitment: felt252,
        encrypted_amount: felt252,
    );
    fn unshield_tokens(
        ref self: TContractState,
        nullifier: felt252,
        amount: u256,
        proof: Span<felt252>,
    );
    fn private_transfer(
        ref self: TContractState,
        input_nullifiers: Span<felt252>,
        output_commitments: Span<felt252>,
        encrypted_outputs: Span<felt252>,
        proof: Span<felt252>,
    );
    fn get_total_shielded(self: @TContractState) -> u256;
    fn is_privacy_enabled(self: @TContractState) -> bool;
    fn is_nullifier_spent(self: @TContractState, nullifier: felt252) -> bool;
}
