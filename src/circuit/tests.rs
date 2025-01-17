use crate::poseidon::params::PoseidonParams;
use crate::rescue::params::RescueParams;
use crate::rescue_prime::params::RescuePrimeParams;
use crate::sponge::GenericSponge;
use crate::tests::init_cs;
use crate::tests::init_rng;
use crate::traits::{CustomGate, HashParams};
use crate::{circuit::sponge::CircuitGenericSponge, tests::init_cs_no_custom_gate};
use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::Field;
use franklin_crypto::plonk::circuit::allocated_num::AllocatedNum;
use franklin_crypto::plonk::circuit::allocated_num::Num;
use franklin_crypto::{bellman::plonk::better_better_cs::cs::ConstraintSystem, bellman::Engine};
use rand::Rand;

pub(crate) fn test_inputs<E: Engine, CS: ConstraintSystem<E>, const N: usize>(
    cs: &mut CS,
    use_allocated: bool,
) -> ([E::Fr; N], [Num<E>; N]) {
    let rng = &mut init_rng();

    let mut inputs = [E::Fr::zero(); N];
    let mut inputs_as_num = [Num::Constant(E::Fr::zero()); N];
    for (i1, i2) in inputs.iter_mut().zip(inputs_as_num.iter_mut()) {
        *i1 = E::Fr::rand(rng);
        *i2 = if use_allocated {
            Num::Variable(AllocatedNum::alloc(cs, || Ok(*i1)).unwrap())
        } else {
            Num::Constant(*i1)
        }
    }

    (inputs, inputs_as_num)
}

fn test_circuit_var_len_generic_hasher<
    E: Engine,
    CS: ConstraintSystem<E>,
    P: HashParams<E, RATE, WIDTH>,
    const RATE: usize,
    const WIDTH: usize,
    const N: usize,
>(
    cs: &mut CS,
    params: &P,
) {
    let (inputs, inputs_as_num) = test_inputs::<E, CS, N>(cs, true);

    let mut hasher = GenericSponge::<_, RATE, WIDTH>::new();
    hasher.absorb_multiple(&inputs, params);
    let expected = hasher.squeeze(params).expect("a squeezed elem");

    let mut circuit_gadget = CircuitGenericSponge::<_, RATE, WIDTH>::new();
    circuit_gadget
        .absorb_multiple(cs, &inputs_as_num, params)
        .unwrap();
    let actual = circuit_gadget
        .squeeze(cs, params)
        .unwrap()
        .expect("a squeezed elem");

    assert_eq!(actual.get_value().unwrap(), expected);
}
// TODO add test for a case when padding needed
fn test_circuit_fixed_len_generic_hasher<
    E: Engine,
    CS: ConstraintSystem<E>,
    P: HashParams<E, RATE, WIDTH>,
    const RATE: usize,
    const WIDTH: usize,
    const N: usize,
>(
    cs: &mut CS,
    params: &P,
) {
    let (inputs, inputs_as_num) = test_inputs::<E, CS, N>(cs, true);

    let expected = GenericSponge::<_, RATE, WIDTH>::hash(&inputs, params, None);

    let actual =
        CircuitGenericSponge::<_, RATE, WIDTH>::hash::<_, P>(cs, &inputs_as_num, &params, None)
            .unwrap();
    assert_eq!(actual[0].get_value().unwrap(), expected[0]);
}

#[test]
fn test_circuit_fixed_len_rescue_hasher() {
    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const INPUT_LENGTH: usize = 2;

    {
        // no custom gate
        let cs = &mut init_cs::<Bn256>();
        let params = RescueParams::default();
        test_circuit_fixed_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of constant length Rescue hash with 2 input(no custom gate): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with state width 3
        let cs = &mut init_cs::<Bn256>();
        let mut params = RescueParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth3);
        test_circuit_fixed_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of constant length Rescue hash with 2 input(custom gate width 3): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with state width 4
        let cs = &mut init_cs::<Bn256>();
        let mut params = RescueParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth4);
        test_circuit_fixed_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of constant length Rescue hash with 2 input(custom gate width 4): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
}

#[test]
fn test_circuit_fixed_len_poseidon_hasher() {
    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const INPUT_LENGTH: usize = 2;

    {
        // no custom gate
        let cs = &mut init_cs::<Bn256>();
        let params = PoseidonParams::default();
        test_circuit_fixed_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of constant length Poseidon hash with 2 input(no custom gate): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with state width 3
        let cs = &mut init_cs::<Bn256>();
        let mut params = PoseidonParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth3);
        test_circuit_fixed_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of constant length Poseidon hash with 2 input(custom gate width 3): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with state width 4
        let cs = &mut init_cs::<Bn256>();
        let mut params = PoseidonParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth4);
        test_circuit_fixed_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of constant length Poseidon hash with 2 input(custom gate width 4): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
}

#[test]
fn test_circuit_fixed_len_rescue_prime_hasher() {
    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const INPUT_LENGTH: usize = 2;

    {
        // no custom gate
        let cs = &mut init_cs::<Bn256>();
        let params = RescuePrimeParams::default();
        test_circuit_fixed_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost constant length RescuePrime hash with 2 input(no custom gate): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with state width 3
        let cs = &mut init_cs::<Bn256>();
        let mut params = RescuePrimeParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth3);
        test_circuit_fixed_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of constant length RescuePrime hash with 2 input(custom gate width 3): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with state width 4
        let cs = &mut init_cs::<Bn256>();
        let mut params = RescuePrimeParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth4);
        test_circuit_fixed_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of constant length RescuePrime hash with 2 input(custom gate width 4): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
}
#[test]
fn test_circuit_var_len_rescue_hasher() {
    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const INPUT_LENGTH: usize = 2;

    {
        // no custom gate
        let cs = &mut init_cs_no_custom_gate::<Bn256>();

        let params = RescueParams::default();
        test_circuit_var_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of variable length Rescue hash with 2 input (no custom gate): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with stare width 3
        let cs = &mut init_cs::<Bn256>();

        let mut params = RescueParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth3);
        test_circuit_var_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of variable length Rescue hash with 2 input(custom gate width 3): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with stare width 4
        let cs = &mut init_cs::<Bn256>();

        let mut params = RescueParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth4);
        test_circuit_var_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of variable length Rescue hash with 2 input(custom gate width 4): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
}

#[test]
fn test_circuit_var_len_poseidon_hasher() {
    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const INPUT_LENGTH: usize = 2;

    {
        // no custom gate
        let cs = &mut init_cs_no_custom_gate::<Bn256>();

        let params = PoseidonParams::default();
        test_circuit_var_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of variable length Poseidon hash with 2 input(no custom gate): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with stare width 3
        let cs = &mut init_cs::<Bn256>();

        let mut params = PoseidonParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth3);
        test_circuit_var_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of variable length Poseidon hash with 2 input(custom gate width 3): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with stare width 4
        let cs = &mut init_cs::<Bn256>();

        let mut params = PoseidonParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth4);
        test_circuit_var_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of variable length Poseidon hash with 2 input(custom gate width 4): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
}

#[test]
fn test_circuit_var_len_rescue_prime_hasher() {
    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const INPUT_LENGTH: usize = 2;

    {
        // no custom gate
        let cs = &mut init_cs_no_custom_gate::<Bn256>();

        let params = RescuePrimeParams::default();
        test_circuit_var_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of variable length RescuePrime hash with 2 input(no custom gate): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with stare width 3
        let cs = &mut init_cs::<Bn256>();

        let mut params = RescuePrimeParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth3);
        test_circuit_var_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of variable length RescuePrime hash with 2 input(custom gate width 3): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with stare width 4
        let cs = &mut init_cs::<Bn256>();

        let mut params = RescuePrimeParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth4);
        test_circuit_var_len_generic_hasher::<_, _, _, RATE, WIDTH, INPUT_LENGTH>(cs, &params);
        println!(
            "CS cost of variable length RescuePrime hash with 2 input(custom gate width 4): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
}

pub(crate) fn test_cipher_inputs<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    input_size: usize,
    use_allocated: bool,
) -> (Vec<E::Fr>, Vec<Num<E>>, E::Fr, Num<E>, E::Fr, Num<E>) {
    let rng = &mut init_rng();

    let mut inputs = vec![];
    let mut inputs_as_num = vec![];
    for _ in 0..input_size {
        let element = E::Fr::rand(rng);
        inputs.push(element.clone());
        let num = if use_allocated {
            Num::Variable(AllocatedNum::alloc(cs, || Ok(element)).unwrap())
        } else {
            Num::Constant(element)
        };
        inputs_as_num.push(num);
    }

    let secret = E::Fr::rand(rng);
    let secret_as_num = Num::Variable(AllocatedNum::alloc(cs, || Ok(secret)).unwrap());
    let nonce = E::Fr::rand(rng);
    let nonce_as_num = Num::Variable(AllocatedNum::alloc(cs, || Ok(nonce)).unwrap());

    (
        inputs,
        inputs_as_num,
        secret,
        secret_as_num,
        nonce,
        nonce_as_num,
    )
}

fn test_circuit_fixed_len_generic_cipher<
    E: Engine,
    CS: ConstraintSystem<E>,
    P: HashParams<E, RATE, WIDTH>,
    const RATE: usize,
    const WIDTH: usize,
>(
    input_len: usize,
    cs: &mut CS,
    params: &P,
) {
    use crate::circuit::poseidon::circuit_poseidon_encrypt;
    use crate::poseidon::cipher::PoseidonCipher;

    let (inputs, inputs_as_num, secret, secret_as_num, nonce, nonce_as_num) =
        test_cipher_inputs::<E, CS>(cs, input_len, true);

    let expected =
        PoseidonCipher::<E, RATE, WIDTH>::encrypt(params, &inputs, &secret, &nonce, None);

    let actual = circuit_poseidon_encrypt::<_, _, _, RATE, WIDTH>(
        cs,
        params,
        None,
        &inputs_as_num,
        &secret_as_num,
        &nonce_as_num,
    )
    .unwrap();
    assert_eq!(actual[0].get_value().unwrap(), expected.cipher[0]);
}

#[test]
fn test_circuit_fixed_len_poseidon_cipher() {
    const WIDTH: usize = 3;
    const RATE: usize = 2;

    {
        // no custom gate
        let cs = &mut init_cs::<Bn256>();
        let params = PoseidonParams::default();
        test_circuit_fixed_len_generic_cipher::<_, _, _, RATE, WIDTH>(2, cs, &params);
        println!(
            "CS cost of constant length Poseidon hash with 2 input(no custom gate): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with state width 3
        let cs = &mut init_cs::<Bn256>();
        let mut params = PoseidonParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth3);
        test_circuit_fixed_len_generic_cipher::<_, _, _, RATE, WIDTH>(2, cs, &params);
        println!(
            "CS cost of constant length Poseidon hash with 2 input(custom gate width 3): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
    {
        // custom gate with state width 4
        let cs = &mut init_cs::<Bn256>();
        let mut params = PoseidonParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth4);
        test_circuit_fixed_len_generic_cipher::<_, _, _, RATE, WIDTH>(2, cs, &params);
        println!(
            "CS cost of constant length Poseidon hash with 2 input(custom gate width 4): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }

    {
        // custom gate with state width 4
        let cs = &mut init_cs::<Bn256>();
        let mut params = PoseidonParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth4);
        test_circuit_fixed_len_generic_cipher::<_, _, _, RATE, WIDTH>(3, cs, &params);
        println!(
            "CS cost of constant length Poseidon hash with 2 input(custom gate width 4): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }

    {
        // custom gate with state width 4
        let cs = &mut init_cs::<Bn256>();
        let mut params = PoseidonParams::default();
        params.use_custom_gate(CustomGate::QuinticWidth4);
        test_circuit_fixed_len_generic_cipher::<_, _, _, RATE, WIDTH>(4, cs, &params);
        println!(
            "CS cost of constant length Poseidon hash with 2 input(custom gate width 4): {}",
            cs.n()
        );

        cs.finalize();
        assert!(cs.is_satisfied());
    }
}
