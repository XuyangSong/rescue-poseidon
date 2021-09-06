use crate::common::domain_strategy::DomainStrategy;
// use crate::poseidon::params::PoseidonParams;
use crate::poseidon::poseidon_round_function;
use franklin_crypto::bellman::{Engine, Field};
use crate::traits::HashParams;

// pub const MESSAGE_SIZE: usize = 2;
// pub const CIPHER_SIZE: usize = MESSAGE_SIZE + 1;

#[derive(Debug, Clone)]
pub struct PoseidonCipher<E: Engine, const RATE: usize, const WIDTH: usize> {
    pub cipher: Vec<E::Fr>,
}

impl<E: Engine, const RATE: usize, const WIDTH: usize> PoseidonCipher<E, RATE, WIDTH> {
    pub fn init_state(
        secret: &E::Fr,
        nonce: &E::Fr,
        input_len: usize,
        domain_strategy: &DomainStrategy,
    ) -> [E::Fr; WIDTH] {
        let mut state = [E::Fr::zero(); WIDTH];

        // specialize capacity
        let capacity_value = domain_strategy
            .compute_capacity::<E>(input_len, RATE)
            .unwrap_or(E::Fr::zero());

        // TBD: if RATE > 2, add state init
        state[0] = capacity_value;
        state[1] = *secret;
        state[2] = *nonce;

        state
    }

    pub fn encrypt<P: HashParams<E, RATE, WIDTH>>(
        params: &P,
        message: &Vec<E::Fr>,
        secret: &E::Fr,
        nonce: &E::Fr,
        domain_strategy: Option<DomainStrategy>,
    ) -> Self {
        let domain_strategy = domain_strategy.unwrap_or(DomainStrategy::CustomFixedLength);
        match domain_strategy {
            DomainStrategy::CustomFixedLength | DomainStrategy::FixedLength => (),
            _ => panic!("only fixed length domain strategies allowed"),
        }

        // Padding
        let padding_values = domain_strategy.generate_padding_values::<E>(message.len(), RATE);

        // chain all values
        let mut padded_input = vec![];
        padded_input.extend_from_slice(message);
        padded_input.extend_from_slice(&padding_values);
        assert!(padded_input.len() % RATE == 0);

        // Init state
        let mut state = Self::init_state(secret, nonce, padded_input.len(), &domain_strategy);

        // Encrypt: process each chunk of message
        let mut cipher = Vec::with_capacity(padded_input.len() + 1);
        for values in padded_input.chunks_exact(RATE) {
            poseidon_round_function(params, &mut state, None);
            for (v, s) in values.iter().zip(state.iter_mut()) {
                s.add_assign(v);
                cipher.push(s.clone());
            }
        }

        // Nonce
        poseidon_round_function(params, &mut state, None);
        cipher.push(state[1]);

        Self { cipher }
    }

    pub fn decrypt<P: HashParams<E, RATE, WIDTH>>(
        &self,
        params: &P,
        secret: &E::Fr,
        nonce: &E::Fr,
        domain_strategy: Option<DomainStrategy>,
    ) -> Vec<E::Fr> {
        assert!(self.cipher.len() > RATE, "cipher length must be larger than RATE");
        let domain_strategy = domain_strategy.unwrap_or(DomainStrategy::CustomFixedLength);
        match domain_strategy {
            DomainStrategy::CustomFixedLength | DomainStrategy::FixedLength => (),
            _ => panic!("only fixed length domain strategies allowed"),
        }

        let message_len = self.cipher.len() - 1;
        let mut message: Vec<E::Fr> = Vec::with_capacity(message_len);

        // Init state
        let mut state = Self::init_state(secret, nonce, message_len, &domain_strategy);

        // Decrypt
        for values in self.cipher.chunks_exact(RATE) {
            poseidon_round_function(params, &mut state, None);
            for (v, s) in values.iter().zip(state.iter_mut()) {
                let mut plain_text = *v;
                plain_text.sub_assign(s);
                message.push(plain_text);
                (*s) = *v;
            }
        }

        // Check Nonce
        poseidon_round_function(params, &mut state, None);
        assert_eq!(self.cipher.last().copied(), Some(state[1]));

        message
    }
}
