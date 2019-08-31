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
fn example_gadget<CS: ConstraintSystem>(cs: &mut CS,a: LinearCombination,c: LinearCombination,) {
    let (_, _, c_var) = cs.multiply(a.clone(), a.clone());
    let lc:LinearCombination = LinearCombination::from(c_var);
    let (_, _, c_var2) = cs.multiply(lc, a.clone());
    cs.constrain(c_var2 + a + Scalar::from(5u64) - c);
}
fn example_gadget_proof(pc_gens: &PedersenGens,bp_gens: &BulletproofGens,x: u64,c: u64,) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");
    let mut prover = Prover::new(pc_gens, &mut transcript);
    let (commitments, vars): (Vec<_>, Vec<_>) = [x, c].into_iter().map(|x| prover.commit(Scalar::from(*x), Scalar::random(&mut thread_rng()))).unzip();
    example_gadget(&mut prover,vars[0].into(),Scalar::from(c).into(),);
    let proof = prover.prove(bp_gens)?;
    Ok((proof, commitments))
}
fn example_gadget_verify(pc_gens: &PedersenGens,bp_gens: &BulletproofGens,c: u64,proof: R1CSProof,commitments: Vec<CompressedRistretto>,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");
    let mut verifier = Verifier::new(&mut transcript);
    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();
    example_gadget(&mut verifier,vars[0].into(),Scalar::from(c).into(),);
    verifier.verify(&proof, &pc_gens, &bp_gens).map_err(|_| R1CSError::VerificationError)
}
fn example_gadget_helper(a: u64,c: u64,) -> Result<(), R1CSError> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let (proof, commitments) = example_gadget_proof(&pc_gens, &bp_gens, a,c)?;
    example_gadget_verify(&pc_gens, &bp_gens, c, proof, commitments)
}
#[test]
fn example_gadget_test() {
    assert!(example_gadget_helper(3, 35).is_ok());
    assert!(example_gadget_helper(4,  35).is_err());
}
fn example_gadget_roundtrip_serialization_helper(a: u64,
    c: u64,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let (proof, commitments) = example_gadget_proof(&pc_gens, &bp_gens, a, c)?;

    let proof = proof.to_bytes();

    let proof = R1CSProof::from_bytes(&proof)?;

    example_gadget_verify(&pc_gens, &bp_gens, c, proof, commitments)
}




// #[test]
// fn example_gadget_serialization_test() {
//     // (3 + 4) * (6 + 1) = (40 + 9)
//     assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 9).is_ok());
//     // (3 + 4) * (6 + 1) != (40 + 10)
//     assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 10).is_err());
// }
