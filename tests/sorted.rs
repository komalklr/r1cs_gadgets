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

use practice::r1cs_utils::{AllocatedScalar, constrain_lc_with_scalar,positive_no_gadget,AllocatedQuantity};
use practice::non_zero::is_nonzero_gadget;


pub fn is_sorted_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
   diff_vars: Vec<AllocatedQuantity>,
    list: &[u64]
) -> Result<(), R1CSError> {
    let set_length = diff_vars.len();
    let n:usize = 64usize;
    for i in 0..set_length {
        // Since `diff_vars[i]` is `set[i] - v`, `diff_vars[i]` + `v` should be `set[i]`
        constrain_lc_with_scalar::<CS>(cs,LinearCombination::from( diff_vars[i].variable) , &Scalar::from(list[i+1]-list[i]));

        // Ensure `set[i] - v` is non-zero
        positive_no_gadget(cs, diff_vars[i],n)?;
    }

    Ok(())
}

/// Prove that difference between each set element and value is non-zero, hence value does not equal any set element.
pub fn gen_proof_of_sorted<R: RngCore + CryptoRng>(randomness: Option<Scalar>, list: &[u64],
                                                             mut rng: &mut R, transcript_label: &'static [u8],
                                                             pc_gens: &PedersenGens, bp_gens: &BulletproofGens) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let list_length = list.len();
    let mut comms: Vec<CompressedRistretto> = vec![];
    let mut diff_vars: Vec<AllocatedQuantity> = vec![];
   // let mut diff_inv_vars: Vec<AllocatedScalar> = vec![];

    let mut prover_transcript = Transcript::new(transcript_label);
    let mut rng = rand::thread_rng();

    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
    // let value= Scalar::from(value);
    // let (com_value, var_value) = prover.commit(value.clone(), randomness.unwrap_or_else(|| Scalar::random(&mut rng)));
    // let alloc_scal = AllocatedScalar {
    //     variable: var_value,
    //     assignment: Some(value),
    // };
    // comms.push(com_value);

    for i in 0..list_length-1 {
        let elem = list[i];
        let elem1 = list[i+1];
        let diff = elem1 - elem;
        let diff_scalar = Scalar::from(diff);
       // let diff_inv = diff.invert();

        // Take difference of set element and value, `set[i] - value`
        let (com_diff, var_diff) = prover.commit(diff_scalar.clone(), Scalar::random(&mut rng));
        let alloc_scal_diff = AllocatedQuantity {
            variable: var_diff,
            assignment: Some(diff),
        };
        diff_vars.push(alloc_scal_diff);
        comms.push(com_diff);

        // Inverse needed to prove that difference `set[i] - value` is non-zero
        // let (com_diff_inv, var_diff_inv) = prover.commit(diff_inv.clone(), Scalar::random(&mut rng));
        // let alloc_scal_diff_inv = AllocatedScalar {
        //     variable: var_diff_inv,
        //     assignment: Some(diff_inv),
        // };
        // diff_inv_vars.push(alloc_scal_diff_inv);
        // comms.push(com_diff_inv);
    }
            println!("2");

    assert!(is_sorted_gadget(&mut prover, diff_vars,&list).is_ok());
        println!("3");

//            println!("For set size {}, no of constraints is {}", &set_length, &prover.num_constraints());

    let proof = prover.prove(&bp_gens)?;
        println!("4");

    Ok((proof, comms))
}

pub fn verify_proof_of_sorted(
                                        proof: R1CSProof, commitments: Vec<CompressedRistretto>,
                                        transcript_label: &'static [u8], pc_gens: &PedersenGens, bp_gens: &BulletproofGens) -> Result<(), R1CSError> {
    let com_length = commitments.len();
    let mut verifier_transcript = Transcript::new(transcript_label);
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let mut diff_vars: Vec<AllocatedQuantity> = vec![];
    //let mut diff_inv_vars: Vec<AllocatedScalar> = vec![];

    // let var_val = verifier.commit(commitments[0]);
    // let alloc_scal = AllocatedScalar {
    //     variable: var_val,
    //     assignment: None,
    // };

    for i in 0..com_length {
        let var_diff = verifier.commit(commitments[i]);
        let alloc_scal_diff = AllocatedQuantity {
            variable: var_diff,
            assignment: None,
        };
        diff_vars.push(alloc_scal_diff);

        // let var_diff_inv = verifier.commit(commitments[2*i]);
        // let alloc_scal_diff_inv = AllocatedScalar {
        //     variable: var_diff_inv,
        //     assignment: None,
        // };
        // diff_inv_vars.push(alloc_scal_diff_inv);
    }

    //assert!(set_non_membership_gadget(&mut verifier, alloc_scal, diff_vars, diff_inv_vars, &set).is_ok());

    verifier.verify(&proof, &pc_gens, &bp_gens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use merlin::Transcript;

    #[test]
    fn set_non_membership_check_gadget() {
        let set: Vec<u64> = vec![2, 3, 5, 6, 8, 20, 25,124];
        //let value = 124u64;
        let mut rng = rand::thread_rng();

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(512, 1);
        let label= b"SetSortedTest";
        let randomness = Some(Scalar::random(&mut rng));
        println!("1");
        let (proof, commitments) = gen_proof_of_sorted(randomness, &set, &mut rng, label, &pc_gens, &bp_gens).unwrap();
        verify_proof_of_sorted(proof, commitments, label, &pc_gens, &bp_gens).unwrap();
    }
}
