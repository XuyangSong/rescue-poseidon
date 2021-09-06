use super::matrix::{matrix_vector_product, mul_by_sparse_matrix};
use super::sbox::sbox;
use super::sponge::circuit_generic_hash_num;
use crate::traits::{HashFamily, HashParams};
use crate::{poseidon::params::PoseidonParams, DomainStrategy};
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::{Field, SynthesisError};
use franklin_crypto::{
    bellman::Engine,
    plonk::circuit::{allocated_num::Num, linear_combination::LinearCombination},
};
use std::convert::TryInto;

/// Receives inputs whose length `known` prior(fixed-length).
/// Also uses custom domain strategy which basically sets value of capacity element to
/// length of input and applies a padding rule which makes input size equals to multiple of
/// rate parameter.
/// Uses pre-defined state-width=3 and rate=2.
pub fn circuit_poseidon_hash<E: Engine, CS: ConstraintSystem<E>, const L: usize>(
    cs: &mut CS,
    input: &[Num<E>; L],
    domain_strategy: Option<DomainStrategy>,
) -> Result<[Num<E>; 2], SynthesisError> {
    const WIDTH: usize = 3;
    const RATE: usize = 2;
    let params = PoseidonParams::<E, RATE, WIDTH>::default();
    circuit_generic_hash_num(cs, input, &params, domain_strategy)
}

pub(crate) fn circuit_poseidon_round_function<
    E: Engine,
    CS: ConstraintSystem<E>,
    P: HashParams<E, RATE, WIDTH>,
    const RATE: usize,
    const WIDTH: usize,
>(
    cs: &mut CS,
    params: &P,
    state: &mut [LinearCombination<E>; WIDTH],
) -> Result<(), SynthesisError> {
    assert_eq!(
        params.hash_family(),
        HashFamily::Poseidon,
        "Incorrect hash family!"
    );
    assert!(params.number_of_full_rounds() % 2 == 0);

    let half_of_full_rounds = params.number_of_full_rounds() / 2;

    let (m_prime, sparse_matrixes) = &params.optimized_mds_matrixes();
    let optimized_round_constants = &params.optimized_round_constants();

    // first full rounds
    for round in 0..half_of_full_rounds {
        let round_constants = &optimized_round_constants[round];

        // add round constatnts
        for (s, c) in state.iter_mut().zip(round_constants.iter()) {
            s.add_assign_constant(*c);
        }
        // non linear sbox
        sbox(
            cs,
            params.alpha(),
            state,
            Some(0..WIDTH),
            params.custom_gate(),
        )?;

        // mul state by mds
        matrix_vector_product(&params.mds_matrix(), state)?;
    }

    state
        .iter_mut()
        .zip(optimized_round_constants[half_of_full_rounds].iter())
        .for_each(|(a, b)| a.add_assign_constant(*b));

    matrix_vector_product(&m_prime, state)?;

    let mut constants_for_partial_rounds = optimized_round_constants
        [half_of_full_rounds + 1..half_of_full_rounds + params.number_of_partial_rounds()]
        .to_vec();
    constants_for_partial_rounds.push([E::Fr::zero(); WIDTH]);
    // in order to reduce gate number we merge two consecutive iteration
    // which costs 2 gates per each

    for (round_constant, sparse_matrix) in constants_for_partial_rounds
        [..constants_for_partial_rounds.len() - 1]
        .chunks(2)
        .zip(sparse_matrixes[..sparse_matrixes.len() - 1].chunks(2))
    {
        // first
        sbox(cs, params.alpha(), state, Some(0..1), params.custom_gate())?;
        state[0].add_assign_constant(round_constant[0][0]);
        mul_by_sparse_matrix(&sparse_matrix[0], state);

        // second
        sbox(cs, params.alpha(), state, Some(0..1), params.custom_gate())?;
        state[0].add_assign_constant(round_constant[1][0]);
        mul_by_sparse_matrix(&sparse_matrix[1], state);
        // reduce gate cost: LC -> Num -> LC
        for state in state.iter_mut() {
            let num = state.clone().into_num(cs).expect("a num");
            *state = LinearCombination::from(num.get_variable());
        }
    }

    sbox(cs, params.alpha(), state, Some(0..1), params.custom_gate())?;
    state[0].add_assign_constant(constants_for_partial_rounds.last().unwrap()[0]);
    mul_by_sparse_matrix(&sparse_matrixes.last().unwrap(), state);

    // second full round
    for round in (params.number_of_partial_rounds() + half_of_full_rounds)
        ..(params.number_of_partial_rounds() + params.number_of_full_rounds())
    {
        let round_constants = &optimized_round_constants[round];

        // add round constatnts
        for (s, c) in state.iter_mut().zip(round_constants.iter()) {
            s.add_assign_constant(*c);
        }

        sbox(
            cs,
            params.alpha(),
            state,
            Some(0..WIDTH),
            params.custom_gate(),
        )?;

        // mul state by mds
        matrix_vector_product(&params.mds_matrix(), state)?;
    }

    Ok(())
}

pub(crate) fn circuit_poseidon_encrypt<
    E: Engine,
    CS: ConstraintSystem<E>,
    P: HashParams<E, RATE, WIDTH>,
    const RATE: usize,
    const WIDTH: usize,
>(
    cs: &mut CS,
    params: &P,
    domain_strategy: Option<DomainStrategy>,
    input: &Vec<Num<E>>,
    secret: &Num<E>,
    nonce: &Num<E>,
) -> Result<Vec<LinearCombination<E>>, SynthesisError> {
    let domain_strategy = domain_strategy.unwrap_or(DomainStrategy::CustomFixedLength);
    match domain_strategy {
        DomainStrategy::CustomFixedLength | DomainStrategy::FixedLength => (),
        _ => panic!("only fixed length domain strategies allowed"),
    }

    // Compute padding values
    let padding_values = domain_strategy
        .generate_padding_values::<E>(input.len(), RATE)
        .iter()
        .map(|el| Num::Constant(*el))
        .collect::<Vec<Num<E>>>();

    // Chain all values
    let mut padded_input = vec![];
    padded_input.extend_from_slice(input);
    padded_input.extend_from_slice(&padding_values);

    assert!(padded_input.len() % RATE == 0);

    // Init state
    let mut state: [LinearCombination<E>; WIDTH] = (0..WIDTH)
        .map(|_| LinearCombination::zero())
        .collect::<Vec<LinearCombination<E>>>()
        .try_into()
        .expect("constant array of LCs");

    // Specialize capacity
    let capacity_value = domain_strategy
        .compute_capacity::<E>(padded_input.len(), RATE)
        .unwrap_or(E::Fr::zero());
    state[0].add_assign_constant(capacity_value);
    state[1].add_assign_number_with_coeff(secret, E::Fr::one());
    state[2].add_assign_number_with_coeff(nonce, E::Fr::one());

    // Prepare output
    let mut output = Vec::with_capacity(padded_input.len() + 1);
    for values in padded_input.chunks_exact(RATE) {
        circuit_poseidon_round_function(cs, params, &mut state)?;
        for (v, s) in values.iter().zip(state.iter_mut()) {
            s.add_assign_number_with_coeff(v, E::Fr::one());
            output.push(s.clone());
        }
    }

    // Nonce
    circuit_poseidon_round_function(cs, params, &mut state)?;
    output.push(state[1].clone());

    Ok(output.try_into().expect("array"))
}
