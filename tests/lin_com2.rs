#![allow(non_snake_case)]
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate csv;
extern crate rustc_serialize;
use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use std::fs::File;
use serde::Deserialize;
use std::error::Error;
// #[derive(Debug, Deserialize)]
// struct Recordn {
//     name: String,
//     noOfTerms: u64,
// }
#[derive(Debug, Deserialize)]
struct Record {
    #[serde(deserialize_with = "csv::invalid_option")]
    index: Option<String>,
    #[serde(deserialize_with = "csv::invalid_option")]
    coeff: Option<u64>,
}

// fn example() -> Result<(), Box<::std::error::Error>> {
//   let file = File::open("constraint.csv").expect("Couldn't open input");
//     let mut rdr = csv::Reader::from_reader(file);
//     for result in rdr.deserialize() {
//         // Notice that we need to provide a type hint for automatic
//         // deserialization.
//         let record: Record = result?;
//         println!("{:?}", record);
//     }
//     Ok(())
// }
fn example_gadget<CS: ConstraintSystem>(cs: &mut CS,a: LinearCombination,c: LinearCombination,) -> Result<(), Box<::std::error::Error>>{
    let file = File::open("constraint.csv").expect("Couldn't open input");
    let mut rdr = csv::Reader::from_reader(file);
    let lcs1:LinearCombination = LinearCombination::from(Scalar::one());
    let mut lc:LinearCombination = LinearCombination::from(Scalar::zero());
    let mut vecl = vec![lcs1.clone(); 10];
    let mut vecABC = vec![lcs1; 2];
    let mut vi:usize = 0;
    let mut flag:bool;
    vecl[1]=c.clone();
    vecl[2]=a;
    let mut k:u64 = 1u64;
    let mut p:u64 = 0;
    for result in rdr.deserialize() 
    {   
        if k<=3{
        k=k+1;
        continue;
        }
        let record: Record = result?;
        if record.coeff.is_none(){
            //assert_eq!(record.index.expect("Constraint Error"), "Constraint 1:");
        }
        else
        {
            match &record.index.clone().unwrap()[..] 
            {
                "A:" => {flag=true;vi=0},
                "B:" => {flag=true;vi=1},
                "C:" => {flag=true;vi=2},
                _ => flag=false,
            }
            if flag==false
            {
                let index:usize = (record.index.unwrap()).parse::<u64>().unwrap() as usize;
                if p>0
                {
                    p=p-1;
                    if vi==2
                    {
                        let (_, _, sym_1) = cs.multiply(vecABC[0].clone(),vecABC[1].clone());
                        vecl[index] = LinearCombination::from(sym_1);
                    }
                    else
                    {
                        lc = lc + (vecl[index].clone())*(Scalar::from(record.coeff.unwrap()));
                        if p==0
                        {
                            vecABC[vi]=lc.clone();
                        }
                    }
                }
            }
            else
            {
                p = record.coeff.unwrap();
                lc=LinearCombination::from(Scalar::zero());
            }
        }
    }
    cs.constrain(vecl[1].clone()-c);
    // let lc1:LinearCombination = LinearCombination::from(Scalar::one());

    // let (_, _, sym_1) = cs.multiply(a.clone(), a.clone());

    // let lcsym_1:LinearCombination = LinearCombination::from(sym_1);
    // let (_, _, y) = cs.multiply(lcsym_1, a.clone());

    // let lcy:LinearCombination = LinearCombination::from(y);
    // let (_, _, sym_2) = cs.multiply(lcy+a.clone(),lc1.clone());

    // let lcsym_2:LinearCombination = LinearCombination::from(sym_2);
    // let (_, _, out) = cs.multiply(lcsym_2+Scalar::from(5u64),lc1);

    // cs.constrain(out-c);
    Ok(())
}  

fn example_gadget_proof(pc_gens: &PedersenGens,bp_gens: &BulletproofGens,x: u64,c: u64,) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");
    let mut prover = Prover::new(pc_gens, &mut transcript);
    let (commitments, vars): (Vec<_>, Vec<_>) = [x].into_iter().map(|x| prover.commit(Scalar::from(*x), Scalar::random(&mut thread_rng()))).unzip();
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
    println!("ggggg1");
    let (proof, commitments) = example_gadget_proof(&pc_gens, &bp_gens, a,c)?;
    println!("ggggg2");
    example_gadget_verify(&pc_gens, &bp_gens, c, proof, commitments)
}
#[test]
fn example_gadget_test() {
    assert!(example_gadget_helper(3, 35).is_ok());
   // assert!(example_gadget_helper(35,  35).is_err());
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
