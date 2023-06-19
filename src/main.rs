use mcl_rust::{G1, G2, GT};
use miracl_core_bls12381::{bls12381::{ecp2::ECP2, ecp::ECP, big::{BIG, self}, pair::{g1mul, g2mul}, bls, fp2::FP2, fp::FP}};
use miracl_core_bls12381::bls12381::rom;
use rand::Rng;
use sha2::Sha512;
use sha2::Digest;

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

fn mx_gen() -> (G2, ECP2) {
    let raw = "1 2345388737500083945391657505708625859903954047151773287623537600586029428359739211026111121073980842558223033704140 3558041178357727243543283929018475959655787667816024413880422701270944718005964809191925861299660390662341819212979 1111454484298065649047920916747797835589661734985194316226909186591481448224600088430816898704234962594609579273169 3988173108836042169913782128392219399166696378042311135661652175544044220584995583525611110036064603671142074680982";
    let mcgen = G2::from_str(raw, 10).unwrap();
    let rawhex = mcgen.get_str(16);

    let mut sraw = rawhex.split(" ");
    let _ = sraw.next().unwrap();
    let rxa = sraw.next().unwrap().to_uppercase();
    let rxb = sraw.next().unwrap().to_uppercase();
    let rya = sraw.next().unwrap().to_uppercase();
    let ryb = sraw.next().unwrap().to_uppercase();

    let xa = &BIG::fromstring(rxa);
    let xb = &BIG::fromstring(rxb);
    let ya = &BIG::fromstring(rya);
    let yb = &BIG::fromstring(ryb);

    let x = FP2::new_bigs(xa, xb);
    let y = FP2::new_bigs(ya, yb);

    let gen = ECP2::new_fp2s(&x, &y);

    (mcgen, gen)
}

fn check_qr(x: &FP, jacobi: isize) -> Option<ECP> {
    let mut res = ECP::new_big(&x.redc());
    if res.is_infinity() {
        return None;
    }

    if res.getpy().jacobi() != jacobi {
        res.neg();
    }

    Some(res)
}

fn calc_bn(fp: &FP) -> ECP {
    let neg = FP::new_copy(fp).jacobi();
    assert!(!fp.iszilch());

    let mut w = FP::new_copy(fp); 
    w.sqr();

    let c1 = FP::new_big(&BIG::fromstring("be32ce5fbeed9ca374d38c0ed41eefd5bb675277cdf12d11bc2fb026c41400045c03fffffffdfffd".to_string()));
    let c2 = FP::new_big(&BIG::fromstring("5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe".to_string()));

    w.add(&FP::new_int(4));
    w.add(&FP::new_int(1));
    assert!(!w.iszilch());
    w.inverse(None);
    w.mul(&c1);
    w.mul(fp);

    let mut x = FP::new_copy(&w);
    x.mul(fp);
    x.neg();
    x.add(&c2);
    if let Some(p) = check_qr(&x, neg) {
        return p;
    }

    x.neg();
    x.sub(&FP::new_int(1));
    if let Some(p) = check_qr(&x, neg) {
        return p;
    }

    x = FP::new_copy(&w);
    x.sqr();
    x.inverse(None);
    x.add(&FP::new_int(1));
    check_qr(&x, neg).unwrap()
}

fn h2f(msg: &[u8]) -> FP {
    let dst = &mut Sha512::digest(msg)[..48];
    dst.reverse();
    let mut big = BIG::frombytes(dst);
    big.mod2m(381);
    let p = BIG { w: rom::MODULUS };
    if BIG::comp(&big, &p) >= 0 {
        big.mod2m(380);
    }
    FP::new_big(&big)
}

fn h2p(msg: &[u8]) -> ECP {
    let fp = h2f(msg);

    let mut p= calc_bn(&fp);
    let cf = BIG::fromstring("396c8c005555e1568c00aaab0000aaab".to_string());

    p = p.mul(&cf);
    p
}

fn main() {
    mcl_rust::init(mcl_rust::CurveType::BLS12_381);

    // generator
    let (mut mcgen, gen) = mx_gen();

    // keygen
    let seed = rand::thread_rng().gen::<[u8; 32]>();
    let (sk, _) = keypair_from_seed(&seed);
    let pk = g2mul(&gen, &sk);
    let mut mcpk = conv_gp2(pk);

    let data: &[u8] = b"test1234567890345689231test12339";

    // Hash to point
    let mut datag1 = unsafe { G1::uninit() };
    datag1.set_hash_of(data);
    println!("datag1 {}", datag1.get_str(16));
    let mirmsg = h2p(data);
    println!("mirmsg {}", mirmsg.tostring().to_ascii_lowercase());

    // signing
    let sig = g1mul(&mirmsg, &sk); 
    let mut mcsig = conv_gp(sig);

    // we send this to chain
    println!("sig {}", hex::encode(mcsig.serialize()));
    println!("pk {}", hex::encode(mcpk.serialize()));
    println!("msg {}", hex::encode(data));

    // verify
    let mut gt1 = unsafe { GT::uninit() };
    let mut gt2 = unsafe { GT::uninit() };
    mcl_rust::pairing(&mut gt1, &mut datag1, &mut mcpk);
    mcl_rust::pairing(&mut gt2, &mut mcsig, &mut mcgen);

    println!("verification res {}", gt1 == gt2);
}
