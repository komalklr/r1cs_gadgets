#![allow(non_snake_case)]

extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;

// fn example_gadget<CS: ConstraintSystem>(
//     cs: &mut CS,
//     a1: LinearCombination,
//     a2: LinearCombination,
//     b1: LinearCombination,
//     b2: LinearCombination,
//     c1: LinearCombination,
//     c2: LinearCombination,
// ) {
//     let (_, _, c_var) = cs.multiply(a1 + a2, b1 + b2);
//     cs.constrain(c1 + c2 - c_var);
// }

// // Prover's scope
// fn example_gadget_proof(
//     pc_gens: &PedersenGens,
//     bp_gens: &BulletproofGens,
//     a1: u64,
//     a2: u64,
//     b1: u64,
//     b2: u64,
//     c1: u64,
//     c2: u64,
// ) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
//     let mut transcript = Transcript::new(b"R1CSExampleGadget");

//     // 1. Create a prover
//     let mut prover = Prover::new(pc_gens, &mut transcript);

//     // 2. Commit high-level variables
//     let (commitments, vars): (Vec<_>, Vec<_>) = [a1, a2, b1, b2, c1]
//         .into_iter()
//         .map(|x| prover.commit(Scalar::from(*x), Scalar::random(&mut thread_rng())))
//         .unzip();

//     // 3. Build a CS
//     example_gadget(
//         &mut prover,
//         vars[0].into(),
//         vars[1].into(),
//         vars[2].into(),
//         vars[3].into(),
//         vars[4].into(),
//         Scalar::from(c2).into(),
//     );

//     // 4. Make a proof
//     let proof = prover.prove(bp_gens)?;

//     Ok((proof, commitments))
// }


// // Verifier logic
// fn example_gadget_verify(
//     pc_gens: &PedersenGens,
//     bp_gens: &BulletproofGens,
//     c2: u64,
//     proof: R1CSProof,
//     commitments: Vec<CompressedRistretto>,
// ) -> Result<(), R1CSError> {
//     let mut transcript = Transcript::new(b"R1CSExampleGadget");

//     // 1. Create a verifier
//     let mut verifier = Verifier::new(&mut transcript);

//     // 2. Commit high-level variables
//     let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

//     // 3. Build a CS
//     example_gadget(
//         &mut verifier,
//         vars[0].into(),
//         vars[1].into(),
//         vars[2].into(),
//         vars[3].into(),
//         vars[4].into(),
//         Scalar::from(c2).into(),
//     );

//     // 4. Verify the proof
//     verifier
//         .verify(&proof, &pc_gens, &bp_gens)
//         .map_err(|_| R1CSError::VerificationError)
// }


// fn example_gadget_roundtrip_helper(
//     a1: u64,
//     a2: u64,
//     b1: u64,
//     b2: u64,
//     c1: u64,
//     c2: u64,
// ) -> Result<(), R1CSError> {
//     // Common
//     let pc_gens = PedersenGens::default();
//     let bp_gens = BulletproofGens::new(128, 1);

//     let (proof, commitments) = example_gadget_proof(&pc_gens, &bp_gens, a1, a2, b1, b2, c1, c2)?;

//     example_gadget_verify(&pc_gens, &bp_gens, c2, proof, commitments)
// }

// fn example_gadget_roundtrip_serialization_helper(
//     a1: u64,
//     a2: u64,
//     b1: u64,
//     b2: u64,
//     c1: u64,
//     c2: u64,
// ) -> Result<(), R1CSError> {
//     // Common
//     let pc_gens = PedersenGens::default();
//     let bp_gens = BulletproofGens::new(128, 1);

//     let (proof, commitments) = example_gadget_proof(&pc_gens, &bp_gens, a1, a2, b1, b2, c1, c2)?;

//     let proof = proof.to_bytes();

//     let proof = R1CSProof::from_bytes(&proof)?;

//     example_gadget_verify(&pc_gens, &bp_gens, c2, proof, commitments)
// }


// #[test]
// fn example_gadget_test() {
//     // (3 + 4) * (6 + 1) = (40 + 9)
//     assert!(example_gadget_roundtrip_helper(3, 4, 6, 1, 40, 9).is_ok());
//     // (3 + 4) * (6 + 1) != (40 + 10)
//     assert!(example_gadget_roundtrip_helper(3, 4, 6, 1, 40, 10).is_err());
// }

// #[test]
// fn example_gadget_serialization_test() {
//     // (3 + 4) * (6 + 1) = (40 + 9)
//     assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 9).is_ok());
//     // (3 + 4) * (6 + 1) != (40 + 10)
//     assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 10).is_err());
// }
fn example_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    a: LinearCombination,
    b: LinearCombination,
    c: LinearCombination,
) {
    let (_, _, c_var) = cs.multiply(a, b);
    cs.constrain(c - c_var);
}

// Prover's scope
fn example_gadget_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    a: u64,
    b: u64,
    c: u64,
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // 2. Commit high-level variables
    let (commitments, vars): (Vec<_>, Vec<_>) = [a, b, c]
        .into_iter()
        .map(|x| prover.commit(Scalar::from(*x), Scalar::random(&mut thread_rng())))
        .unzip();

    // 3. Build a CS
    example_gadget(
        &mut prover,
        vars[0].into(),
        vars[1].into(),
        Scalar::from(c).into(),
    );

    // 4. Make a proof
    let proof = prover.prove(bp_gens)?;

    Ok((proof, commitments))
}


// Verifier logic
fn example_gadget_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    c: u64,
    proof: R1CSProof,
    commitments: Vec<CompressedRistretto>,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");

    // 1. Create a verifier
    let mut verifier = Verifier::new(&mut transcript);

    // 2. Commit high-level variables
    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

    // 3. Build a CS
    example_gadget(
        &mut verifier,
        vars[0].into(),
        vars[1].into(),
        Scalar::from(c).into(),
    );

    // 4. Verify the proof
    verifier
        .verify(&proof, &pc_gens, &bp_gens)
        .map_err(|_| R1CSError::VerificationError)
}


fn example_gadget_roundtrip_helper(
    a: u64,
    b: u64,
    c: u64,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let (proof, commitments) = example_gadget_proof(&pc_gens, &bp_gens, a, b, c)?;

    example_gadget_verify(&pc_gens, &bp_gens, c, proof, commitments)
}

fn example_gadget_roundtrip_serialization_helper(
    a: u64,
    b: u64,
    c: u64,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let (proof, commitments) = example_gadget_proof(&pc_gens, &bp_gens, a, b, c)?;

    let proof = proof.to_bytes();

    let proof = R1CSProof::from_bytes(&proof)?;

    example_gadget_verify(&pc_gens, &bp_gens, c, proof, commitments)
}


#[test]
fn example_gadget_test() {
    // (3 + 4) * (6 + 1) = (40 + 9)
    assert!(example_gadget_roundtrip_helper(3, 4, 12).is_ok());
    // (3 + 4) * (6 + 1) != (40 + 10)
    assert!(example_gadget_roundtrip_helper(3, 4, 10).is_err());
}

// #[test]
// fn example_gadget_serialization_test() {
//     // (3 + 4) * (6 + 1) = (40 + 9)
//     assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 9).is_ok());
//     // (3 + 4) * (6 + 1) != (40 + 10)
//     assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 10).is_err());
// }