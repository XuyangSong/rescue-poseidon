mod circuit;
#[allow(dead_code)]
mod common;
pub mod poseidon;
pub mod rescue;
pub mod rescue_prime;
mod sponge;
#[cfg(test)]
mod tests;
mod traits;

pub use circuit::sponge::{
    circuit_generic_hash, circuit_generic_round_function,
    circuit_generic_round_function_conditional, CircuitGenericSponge,
};
pub use common::domain_strategy::DomainStrategy;
pub use poseidon::{params::PoseidonParams, poseidon_hash};
pub use rescue::{params::RescueParams, rescue_hash};
pub use rescue_prime::{params::RescuePrimeParams, rescue_prime_hash};
pub use sponge::{generic_hash, generic_round_function, GenericSponge};
pub use traits::{CustomGate, HashFamily, HashParams};
pub use circuit::poseidon::circuit_poseidon_encrypt;