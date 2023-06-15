use mcl_rust::{G1, G2, GT};
use miracl_core_bls12381::bls12381::{ecp2::ECP2, ecp::ECP, big::{BIG, self}, pair::{g1mul, g2mul}, bls};
use rand::Rng;

pub fn keypair_from_seed(ikm: &[u8; 32]) -> (BIG, ECP2) {
    const MB: usize = 2 * (big::MODBYTES as usize) + 1;
    let mut w = [0u8; MB];
    let mut s = [0u8; big::MODBYTES];

    bls::key_pair_generate(ikm, &mut s, &mut w);
    (BIG::frombytes(&s), ECP2::frombytes(&w))
}

fn conv_gp(mut sig1: ECP) -> G1 {
    sig1.affine();
    let rx = sig1.getpx().tostring().to_ascii_lowercase();
    let ry = sig1.getpy().tostring().to_ascii_lowercase();

    let sf = format!("1 0x{} 0x{}", rx, ry);
    let mcl_sig = G1::from_str(&sf, 16).unwrap();

    assert!(mcl_sig.is_valid(), "badsig");
    
    mcl_sig
}

fn conv_gp2(mut bls12: ECP2) -> G2 {
    bls12.affine();
    let mut x = bls12.getpx();
    let mut y = bls12.getpy();

    let rxa = x.geta().tostring().to_ascii_lowercase();
    let rxb = x.getb().tostring().to_ascii_lowercase();
    let rya = y.geta().tostring().to_ascii_lowercase();
    let ryb = y.getb().tostring().to_ascii_lowercase();

    let sf = format!("1 0x{} 0x{} 0x{} 0x{}", rxa, rxb, rya, ryb);
    let mcbls = G2::from_str(&sf, 16).unwrap();

    assert!(mcbls.is_valid(), "badpk");

    mcbls
}

fn g1_rev(gp1: &G1) -> ECP {
    let raw = gp1.get_str(16);
    let mut sraw = raw.split(" ");
    let _ = sraw.next().unwrap();
    let rx = sraw.next().unwrap().to_uppercase();
    let ry = sraw.next().unwrap().to_uppercase();

    let x = &BIG::fromstring(rx);
    let y = &BIG::fromstring(ry);

    ECP::new_bigs(x, y)
}

fn main() {
    mcl_rust::init(mcl_rust::CurveType::BLS12_381);
    // set mode to MCL_MAP_TO_MODE_HASH_TO_CURVE
    //unsafe { mcl_rust::mclBn_setMapToMode(5) };

    // keygen
    let seed = rand::thread_rng().gen::<[u8; 32]>();
    let (sk, _) = keypair_from_seed(&seed);
    let pk = g2mul(&ECP2::generator(), &sk);
    let mut mcpk = conv_gp2(pk);

    let data: &[u8; 32] = b"test1234567890345689231test12339";

    // Hash to point
    let mut datag1 = unsafe { G1::uninit() };
    datag1.set_hash_of(data);
    let mirmsg = g1_rev(&datag1);

    // signing
    let sig = g1mul(&mirmsg, &sk); 
    let mut mcsig = conv_gp(sig);

    // we send this to chain
    println!("sig {}", hex::encode(mcsig.serialize()));
    println!("pk {}", hex::encode(mcpk.serialize()));
    println!("msg {}", hex::encode(data));

    // verify
    let mut mcgen = conv_gp2(ECP2::generator());
    let mut gt1 = unsafe { GT::uninit() };
    let mut gt2 = unsafe { GT::uninit() };
    mcl_rust::pairing(&mut gt1, &mut datag1, &mut mcpk);
    mcl_rust::pairing(&mut gt2, &mut mcsig, &mut mcgen);

    println!("verification res {}", gt1 == gt2);
}
