extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate practice;

use bulletproofs::r1cs::{ConstraintSystem, R1CSError, R1CSProof, Variable, Prover, Verifier};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use bulletproofs::r1cs::LinearCombination;
use merlin::Transcript;
use rand::{RngCore, CryptoRng};

use practice::r1cs_utils::{AllocatedScalar, constrain_lc_with_scalar, AllocatedQuantity, positive_no_gadget};
use practice::non_zero::is_nonzero_gadget;


pub fn set_non_membership_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    diff_vars: Vec<AllocatedQuantity>,
    set: &[u64]
) -> Result<(), R1CSError> {
    let set_length = diff_vars.len();
    let n:usize = 2usize;
    let x:Variable = diff_vars[0].variable;
    let z_lc: LinearCombination = vec![(x, Scalar::zero())].iter().collect();
    for i in 0..set_length {
        // Since `diff_vars[i]` is `set[i] - v`, `diff_vars[i]` + `v` should be `set[i]`
      //  constrain_lc_with_scalar::<CS>(cs, diff_vars[i].variable + z_lc, &Scalar::from(set[i+1]-set[i]));

        // Ensure `set[i] - v` is non-zero
        positive_no_gadget(cs, diff_vars[i],n)?;
    }

    Ok(())
}

/// Prove that difference between each set element and value is non-zero, hence value does not equal any set element.
pub fn gen_proof_of_set_non_membership<R: RngCore + CryptoRng>( randomness: Option<Scalar>, set: &[u64],
                                                             mut rng: &mut R, transcript_label: &'static [u8],
                                                             pc_gens: &PedersenGens, bp_gens: &BulletproofGens) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let set_length = set.len()-1;
    let mut comms: Vec<CompressedRistretto> = vec![];
    let mut diff_vars: Vec<AllocatedQuantity> = vec![];
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut rng = rand::thread_rng();
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
    
    for i in 0..set_length {
        let elem = set[i];
        let elem1 = set[i+1];
        let diff = elem1 - elem;
        let diff_scl = Scalar::from(diff);
        // println!("{}",diff);
        // println!("{:?}",diff_scl);

        // Take difference of set element and value, `set[i] - value`
        let (com_diff, var_diff) = prover.commit(diff_scl.clone(), Scalar::random(&mut rng));
        let alloc_scal_diff = AllocatedQuantity {
            variable: var_diff,
            assignment: Some(diff),
        };
        diff_vars.push(alloc_scal_diff);
        println!("variable {:?}",alloc_scal_diff);
        comms.push(com_diff);
        // Inverse needed to prove that difference `set[i] - value` is non-zero
    }
   // println!("{:?}",diff_vars.len());
    assert!(set_non_membership_gadget(&mut prover, diff_vars, &set).is_ok());

//            println!("For set size {}, no of constraints is {}", &set_length, &prover.num_constraints());

    let proof = prover.prove(&bp_gens)?;

    Ok((proof, comms))
}

pub fn verify_proof_of_set_non_membership(
                                        proof: R1CSProof, commitments: Vec<CompressedRistretto>,
                                        transcript_label: &'static [u8], pc_gens: &PedersenGens, bp_gens: &BulletproofGens) -> Result<(), R1CSError> {
    let set_length = commitments.len();
    let mut verifier_transcript = Transcript::new(transcript_label);
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let mut diff_vars: Vec<AllocatedQuantity> = vec![];

    // for i in 1..set_length {
    //     let var_diff = verifier.commit(commitments[i]);
    //     let alloc_scal_diff = AllocatedQuantity {
    //         variable: var_diff,
    //         assignment: None,
    //     };
    //     diff_vars.push(alloc_scal_diff);
    // }

   // assert!(set_non_membership_gadget(&mut verifier, alloc_scal, diff_vars, diff_inv_vars, &set).is_ok());

    verifier.verify(&proof, &pc_gens, &bp_gens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use merlin::Transcript;
    // #[test]
    // fn positive_no_gadget_test1(){
    // positive_no_gadget(120u64);
    // }
    // #[test]
    // fn positive_no_gadget_test2(){
    // positive_no_gadget(20u64);
    // }
    // #[test]
    // fn positive_no_gadget_test3(){
    // positive_no_gadget(-40i64);
    // }
    #[test]
    fn set_non_membership_check_gadget() {
        let set: Vec<u64> = vec![2, 3,6];
        let value = 120u64;
        let mut rng = rand::thread_rng();

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(512, 1);
        let label= b"SetNonMemebershipTest";
        let randomness = Some(Scalar::random(&mut rng));
        let (proof, commitments) = gen_proof_of_set_non_membership(randomness, &set, &mut rng, label, &pc_gens, &bp_gens).unwrap();
        verify_proof_of_set_non_membership( proof, commitments, label, &pc_gens, &bp_gens).unwrap();
    }
    
}
