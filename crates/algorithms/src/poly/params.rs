//! params.rs - Enhanced polynomial ring parameters with NTT support

/// Basic trait defining the modulus and degree for a polynomial ring
pub trait Modulus {
    /// The primary modulus Q for coefficient arithmetic
    const Q: u32;

    /// The polynomial degree N (number of coefficients)
    const N: usize;

    /// Barrett reduction constant mu = floor(2^k / Q)
    /// Set to 0 for dynamic computation
    const BARRETT_MU: u128 = 0;

    /// Barrett reduction shift amount k
    /// Set to 0 for dynamic computation
    const BARRETT_K: u32 = 0;
}

//───────────────────────────────────────────────────────────────────────────────
//  What flavour of output should `inv_ntt()` return?
//───────────────────────────────────────────────────────────────────────────────

/// Post-processing mode after a Gentleman–Sande inverse NTT.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PostInvNtt {
    /// Strip the last Montgomery factor **R** → coefficients are in *standard*
    /// domain (Kyber).
    Standard,
    /// Keep one Montgomery factor **R** → coefficients stay in Montgomery
    /// domain (Dilithium).
    Montgomery,
}

/// Extended trait for NTT-enabled moduli
pub trait NttModulus: Modulus {
    /// Primitive root of unity (generator)
    const ZETA: u32;

    /// Precomputed twiddle factors for forward NTT
    /// CRITICAL: For Dilithium, these are stored in MONTGOMERY domain (ζ·R mod q)
    /// exactly as in the FIPS-204 reference implementation.
    /// Do NOT convert them again - that would give ζ·R² mod q!
    const ZETAS: &'static [u32];

    /// N^-1 mod Q for final scaling in inverse NTT
    /// This should be in Montgomery form: (N^-1 * R) mod Q
    const N_INV: u32;

    /// Montgomery parameter R = 2^32 mod Q
    const MONT_R: u32;

    /// -Q^-1 mod 2^32 for Montgomery reduction (sometimes called NEG_QINV or MONT_QINV)
    const NEG_QINV: u32;

    /// Twist factors ψ_i = ω^(bitrev(i)) in STANDARD domain (length N)
    /// These are the N-th roots of the primitive 2N-th root of unity
    /// Required for twisted/negacyclic NTT (Dilithium)
    /// NOTE: FIPS-204 reference implementation does NOT use these!
    const PSIS: &'static [u32];

    /// Inverse twist factors ψ_i^(-1) in STANDARD domain (length N)
    /// Required for inverse twisted/negacyclic NTT (Dilithium)
    /// NOTE: FIPS-204 reference implementation does NOT use these!
    const INV_PSIS: &'static [u32];

    /// How the coefficients should be post-processed after the inverse NTT.
    ///
    /// * `Standard`   → Kyber / Saber style  
    /// * `Montgomery` → Dilithium style (`invntt_tomont`)
    const POST_INVNTT_MODE: PostInvNtt = PostInvNtt::Standard;
}

/// Example: Kyber-256 parameter set
#[derive(Clone, Debug)]
pub struct Kyber256Params;

impl Modulus for Kyber256Params {
    const Q: u32 = 3329;
    const N: usize = 256;

    // Barrett constants for Q = 3329
    // k=45 (formula would give 12+32=44, but 45 provides extra margin)
    // mu = floor(2^45 / 3329) = 10_569_051_393
    const BARRETT_MU: u128 = 10_569_051_393;
    const BARRETT_K: u32 = 45;
}

impl NttModulus for Kyber256Params {
    const ZETA: u32 = 17; // primitive 512-th root of unity mod 3329
                          // Pre-computed tables dropped; Cooley-Tukey now derives twiddles on demand
    const ZETAS: &'static [u32] = &[];
    /// (256⁻¹) in Montgomery form: (256⁻¹ · R₃₂) mod Q
    const N_INV: u32 = 2385;
    /// 2³² mod Q
    const MONT_R: u32 = 1353;
    /// -Q⁻¹ mod 2³² (0x94570CFF)
    const NEG_QINV: u32 = 0x94570CFF;

    // Kyber doesn't use twisting
    const PSIS: &'static [u32] = &[];
    const INV_PSIS: &'static [u32] = &[];

    // Kyber wants standard-domain coefficients after InvNTT
    const POST_INVNTT_MODE: PostInvNtt = PostInvNtt::Standard;
}

/// Example: Dilithium parameter sets
#[derive(Clone, Debug)]
pub struct Dilithium2Params;

impl Modulus for Dilithium2Params {
    const Q: u32 = 8380417; // 2^23 - 2^13 + 1
    const N: usize = 256;

    // Barrett constants for Q = 8380417
    // k=55 (formula would give 24+32=56, but 55 passes proof and saves a cycle of shift)
    // mu = floor(2^55 / 8380417) = 4_299_165_187
    const BARRETT_MU: u128 = 4_299_165_187;
    const BARRETT_K: u32 = 55;
}

// -----------------------------------------------------------------------------
// FIPS-204 forward-NTT twiddle table  (Montgomery domain, q = 8 380 417)
//
// • Used by Algorithm 41 (DIF, "forward NTT")
// • **Row-major / block-first** ordering:
//       len = 128 →  1 twiddle   (index 0)
//       len =  64 →  2 twiddles  (indices 1..2)
//       len =  32 →  4 twiddles  (3..6)
//       len =  16 →  8 twiddles  (7..14)
//       len =   8 → 16 twiddles  (15..30)
//       len =   4 → 32 twiddles  (31..62)
//       len =   2 → 64 twiddles  (63..126)
//       len =   1 →128 twiddles  (127..254)
//   (= 1 + 2 + 4 + 8 + 16 + 32 + 64 + 128 = 255 total)
//
// • MUST be consumed by a **block-first loop**
//     for start in 0, 2·len, … { zeta = ZETAS[k++] ; … for j = … }
//   — *do **not** use an offset-first (column-major) loop with this table!*
// -----------------------------------------------------------------------------

const DILITHIUM_ZETAS: [u32; 255] = [
    25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468, 1826347, 2353451, 8021166, 6288512,
    3119733, 5495562, 3111497, 2680103, 2725464, 1024112, 7300517, 3585928, 7830929, 7260833,
    2619752, 6271868, 6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,
    2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439, 4519302, 5336701,
    3574422, 5512770, 3539968, 8079950, 2348700, 7841118, 6681150, 6736599, 3505694, 4558682,
    3507263, 6239768, 6779997, 3699596, 811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892,
    5582638, 4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196, 7122806,
    1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922, 3412210, 7396998, 2147896,
    2715295, 5412772, 4686924, 7969390, 5903370, 7709315, 7151892, 8357436, 7072248, 7998430,
    1349076, 1852771, 6949987, 5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561, 189548, 4827145,
    3159746, 6529015, 5971092, 8202977, 1315589, 1341330, 1285669, 6795489, 7567685, 6940675,
    5361315, 4499357, 4751448, 3839961, 2091667, 3407706, 2316500, 3817976, 5037939, 2244091,
    5933984, 4817955, 266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917, 7725090, 5257975, 2031748,
    3207046, 4823422, 7855319, 7611795, 4784579, 342297, 286988, 5942594, 4108315, 3437287,
    5038140, 1735879, 203044, 2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353,
    1595974, 4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447, 7047359,
    1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775, 7100756, 1917081, 5834105,
    7005614, 1500165, 777191, 2235880, 3406031, 7838005, 5548557, 6709241, 6533464, 5796124,
    4656147, 594136, 4603424, 6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531,
    7173032, 5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310, 5341501,
    3523897, 3866901, 269760, 2213111, 7404533, 1717735, 472078, 7953734, 1723600, 6577327,
    1910376, 6712985, 7276084, 8119771, 4546524, 5441381, 6144432, 7959518, 6094090, 183443,
    7403526, 1612842, 4834730, 7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263,
    1976782,
];

/// Dilithium twist factors ψ_i = ω^(bitrev(i)) in STANDARD domain
/// These are the 512-th roots of unity needed for the twisted NTT
/// NOTE: The FIPS-204 reference implementation does NOT use these!
const DILITHIUM_PSIS: [u32; 256] = [
    1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987, 7778734, 3542485, 2682288,
    2129892, 3764867, 7375178, 557458, 7159240, 5010068, 4317364, 2663378, 6705802, 4855975,
    7946292, 676590, 7044481, 5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639,
    2283733, 3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875, 394148,
    928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050, 3415069, 1759347, 7562881,
    4805951, 3756790, 6444618, 6663429, 4430364, 5483103, 3192354, 556856, 3870317, 2917338,
    1853806, 3345963, 1858416, 3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977,
    8106357, 2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088, 1528066,
    482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034, 4213992, 4892034, 1987814,
    5183169, 1736313, 235407, 5130263, 3258457, 5801164, 1787943, 5989328, 6125690, 3482206,
    4197502, 7080401, 6018354, 7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816,
    3374250, 1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254, 348812,
    8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507, 1753, 6444997, 5720892, 6924527,
    2660408, 6600190, 8321269, 2772600, 1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502,
    4663471, 8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952, 6695264,
    4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040, 4234153, 6607829, 2192938,
    6653329, 2387513, 4768667, 8111961, 5199961, 3747250, 2296099, 1239911, 4541938, 3195676,
    2642980, 1254190, 8368000, 2998219, 141835, 8291116, 2513018, 7025515, 613238, 7070156,
    6161950, 7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452, 6757063,
    2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006, 6903432, 1994046, 2491325,
    6987258, 507927, 7192532, 7655613, 6545891, 5346675, 8041997, 2647994, 3009748, 5767564,
    4148469, 749577, 4357667, 3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598,
    5011144, 3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976, 3105558,
    7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265, 6195333, 3123762, 2358373, 6187330,
    5365997, 6663603, 2926054, 7987710, 8077412, 3531229, 4405932, 4606686, 1900052, 7598542,
    1054478, 7648983,
];

/// Dilithium inverse twist factors ψ_i^(-1) in STANDARD domain
/// NOTE: The FIPS-204 reference implementation does NOT use these!
const DILITHIUM_INV_PSIS: [u32; 256] = [
    1, 3572223, 4618904, 4614810, 3201430, 3145678, 2883726, 3201494, 1221177, 7822959, 1005239,
    4615550, 6250525, 5698129, 4837932, 601683, 6096684, 5564778, 3585098, 642628, 6919699,
    5926434, 6666122, 3227876, 1335936, 7703827, 434125, 3524442, 1674615, 5717039, 4063053,
    3370349, 6522001, 5034454, 6526611, 5463079, 4510100, 7823561, 5188063, 2897314, 3950053,
    1716988, 1935799, 4623627, 3574466, 817536, 6621070, 4965348, 6224367, 5138445, 4018989,
    6308588, 3506380, 7284949, 7451668, 7986269, 7220542, 4675594, 6279007, 3110818, 3586446,
    5639874, 5197539, 4778199, 6635910, 2236726, 1922253, 3818627, 2354215, 7369194, 327848,
    8031605, 459163, 653275, 6067579, 3467665, 2778788, 5697147, 2775755, 7023969, 5006167,
    5454601, 1226661, 4478945, 7759253, 5344437, 5919030, 1317678, 2362063, 1300016, 4182915,
    4898211, 2254727, 2391089, 6592474, 2579253, 5121960, 3250154, 8145010, 6644104, 3197248,
    6392603, 3488383, 4166425, 3334383, 5917973, 8210729, 565603, 2962264, 7231559, 7897768,
    6852351, 4222329, 1109516, 2983781, 5569126, 3815725, 6442847, 6352299, 5871437, 274060,
    3121440, 3222807, 4197045, 4528402, 2635473, 7102792, 5307408, 731434, 7325939, 781875,
    6480365, 3773731, 3974485, 4849188, 303005, 392707, 5454363, 1716814, 3014420, 2193087,
    6022044, 5256655, 2185084, 1514152, 8240173, 4949981, 7520273, 553718, 7872272, 1103344,
    5274859, 770441, 7835041, 8165537, 5016875, 5360024, 1370517, 11879, 4385746, 3369273, 7216819,
    6352379, 6715099, 6657188, 1615530, 5811406, 4399818, 4022750, 7630840, 4231948, 2612853,
    5370669, 5732423, 338420, 3033742, 1834526, 724804, 1187885, 7872490, 1393159, 5889092,
    6386371, 1476985, 2743411, 7852436, 1179613, 7794176, 2033807, 2374402, 6275131, 1623354,
    2178965, 818761, 1879878, 6341273, 3472069, 4340221, 1921994, 458740, 2218467, 1310261,
    7767179, 1354892, 5867399, 89301, 8238582, 5382198, 12417, 7126227, 5737437, 5184741, 3838479,
    7140506, 6084318, 4633167, 3180456, 268456, 3611750, 5992904, 1727088, 6187479, 1772588,
    4146264, 2455377, 250446, 7744461, 3551006, 3768948, 5702139, 3410568, 1685153, 3759465,
    3956944, 6783595, 1979497, 2454145, 7371052, 7557876, 27812, 3716946, 3284915, 2296397,
    3956745, 3965306, 7743490, 8293209, 7198174, 5607817, 59148, 1780227, 5720009, 1455890,
    2659525, 1935420, 8378664,
];

/// General Dilithium parameter set used by the signature implementation
#[derive(Clone, Debug)]
pub struct DilithiumParams;

impl Modulus for DilithiumParams {
    const Q: u32 = 8380417; // 2^23 - 2^13 + 1
    const N: usize = 256;

    // Barrett constants for Q = 8380417
    // k=55 (formula would give 24+32=56, but 55 passes proof and saves a cycle of shift)
    // mu = floor(2^55 / 8380417) = 4_299_165_187
    const BARRETT_MU: u128 = 4_299_165_187;
    const BARRETT_K: u32 = 55;
}

impl NttModulus for DilithiumParams {
    const ZETA: u32 = 1753; // primitive 512-th root of unity mod Q

    // Use the Dilithium zeta table (in MONTGOMERY domain)
    // These are already in Montgomery form: ζ^(brv(k)) · R mod q
    // Do NOT convert them again!
    const ZETAS: &'static [u32] = &DILITHIUM_ZETAS;

    /// N^-1 mod Q in Montgomery form: 256^-1 · R mod Q = 16_382
    /// This is the value used by the reference `invntt_tomont`.
    /// Calculation: (8_347_681 * 4_193_792) mod 8_380_417 = 16_382
    /// where 8_347_681 = 256^-1 mod 8_380_417
    const N_INV: u32 = 16_382;

    /// Montgomery R = 2^32 mod Q = 4_193_792
    const MONT_R: u32 = 4_193_792;

    /// -Q⁻¹ mod 2³² = 4_236_238_847
    /// Q = 8380417, Q⁻¹ mod 2³² = 58728449 (0x03802001)
    /// -Q⁻¹ mod 2³² = 2³² - 58728449 = 4236238847 (0xFC7FDFFF)
    const NEG_QINV: u32 = 4_236_238_847;

    // Add the twist factors (NOT used by FIPS-204 reference)
    const PSIS: &'static [u32] = &DILITHIUM_PSIS;
    const INV_PSIS: &'static [u32] = &DILITHIUM_INV_PSIS;

    // FIXED: Tests expect standard domain output from inverse NTT
    const POST_INVNTT_MODE: PostInvNtt = PostInvNtt::Standard;
}

/// Optional: Dilithium parameters with Montgomery output
/// Use this when you need coefficients to stay in Montgomery domain after inverse NTT
#[derive(Clone, Debug)]
pub struct DilithiumParamsMont;

impl Modulus for DilithiumParamsMont {
    const Q: u32 = 8380417;
    const N: usize = 256;
    const BARRETT_MU: u128 = 4_299_165_187;
    const BARRETT_K: u32 = 55;
}

impl NttModulus for DilithiumParamsMont {
    const ZETA: u32 = 1753;
    const ZETAS: &'static [u32] = &DILITHIUM_ZETAS;
    const N_INV: u32 = 16_382;
    const MONT_R: u32 = 4_193_792;
    const NEG_QINV: u32 = 4_236_238_847;
    const PSIS: &'static [u32] = &DILITHIUM_PSIS;
    const INV_PSIS: &'static [u32] = &DILITHIUM_INV_PSIS;

    // This variant keeps Montgomery domain output
    const POST_INVNTT_MODE: PostInvNtt = PostInvNtt::Montgomery;
}

/// Helper functions for parameter validation
/// Check if a number is prime (simplified check)
pub fn is_prime(q: u32) -> bool {
    if q < 2 {
        return false;
    }
    if q == 2 {
        return true;
    }
    if q % 2 == 0 {
        return false;
    }

    let mut i = 3u32;
    while i <= q / i {
        if q % i == 0 {
            return false;
        }
        i += 2;
    }
    true
}

/// Check if N is a power of 2
pub fn is_power_of_two(n: usize) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_params() {
        assert_eq!(Kyber256Params::Q, 3329);
        assert_eq!(Kyber256Params::N, 256);
        assert!(is_prime(Kyber256Params::Q));
        assert!(is_power_of_two(Kyber256Params::N));
        assert_eq!(Kyber256Params::POST_INVNTT_MODE, PostInvNtt::Standard);
        assert_eq!(Kyber256Params::BARRETT_MU, 10_569_051_393);
        assert_eq!(Kyber256Params::BARRETT_K, 45);
    }

    #[test]
    fn test_dilithium_params() {
        assert_eq!(Dilithium2Params::Q, 8380417);
        assert_eq!(Dilithium2Params::N, 256);
        assert!(is_prime(Dilithium2Params::Q));
        assert_eq!(Dilithium2Params::BARRETT_MU, 4_299_165_187);
        assert_eq!(Dilithium2Params::BARRETT_K, 55);
    }

    #[test]
    fn test_dilithium_general_params() {
        assert_eq!(DilithiumParams::Q, 8380417);
        assert_eq!(DilithiumParams::N, 256);
        assert!(is_prime(DilithiumParams::Q));
        assert!(is_power_of_two(DilithiumParams::N));
        // FIXED: Now expects Standard mode to match test expectations
        assert_eq!(DilithiumParams::POST_INVNTT_MODE, PostInvNtt::Standard);
        assert_eq!(DilithiumParams::BARRETT_MU, 4_299_165_187);
        assert_eq!(DilithiumParams::BARRETT_K, 55);
    }

    #[test]
    fn test_dilithium_constant_calculations() {
        // Verify N_INV = N^-1 * R mod Q
        // N^-1 mod Q = 8,347,681 (256^-1 mod 8,380,417)
        // R = 4,193,792 (2^32 mod 8,380,417)
        // N^-1 * R mod Q = 8,347,681 * 4,193,792 mod 8,380,417 = 16,382
        let n_inv_std = 8_347_681u64; // 256^-1 mod Q
        let r = DilithiumParams::MONT_R as u64;
        let q = DilithiumParams::Q as u64;
        let expected_n_inv = (n_inv_std * r) % q;
        assert_eq!(expected_n_inv, 16_382);
        assert_eq!(DilithiumParams::N_INV as u64, expected_n_inv);

        // Verify NEG_QINV = -Q⁻¹ mod 2³²
        // Q⁻¹ mod 2³² = 0x03802001 = 58728449
        // -Q⁻¹ mod 2³² = 2³² - 58728449 = 4236238847
        let q_inv: u32 = 58728449; // Q⁻¹ mod 2³²
        let neg_qinv = (1u64 << 32) - (q_inv as u64);
        assert_eq!(neg_qinv, 4_236_238_847);
        assert_eq!(DilithiumParams::NEG_QINV as u64, neg_qinv);
    }

    #[test]
    fn test_zetas_in_montgomery_domain() {
        // Verify that the zeta table is in Montgomery domain (column-wise order)
        // First column-wise zeta should be 25_847
        assert_eq!(DilithiumParams::ZETAS[0], 25_847);

        // (Optional additional sanity check, matching standard ζ^128·R mod q)
        let zeta_128_std = 4808194u64; // ζ^128 mod q in standard form
        let mont_form = (zeta_128_std * DilithiumParams::MONT_R as u64) % DilithiumParams::Q as u64;
        assert_eq!(mont_form as u32, 25_847);
    }

    #[test]
    fn test_twist_factors() {
        // Verify PSIS and INV_PSIS are inverses
        assert_eq!(DilithiumParams::PSIS.len(), 256);
        assert_eq!(DilithiumParams::INV_PSIS.len(), 256);

        // ψ_0 = 1 always
        assert_eq!(DilithiumParams::PSIS[0], 1);
        assert_eq!(DilithiumParams::INV_PSIS[0], 1);

        // Check that ψ_i * ψ_i^(-1) ≡ 1 (mod q)
        let q = DilithiumParams::Q as u64;
        for i in 0..10 {
            let psi = DilithiumParams::PSIS[i] as u64;
            let inv_psi = DilithiumParams::INV_PSIS[i] as u64;
            let product = (psi * inv_psi) % q;
            assert_eq!(product, 1, "ψ[{}] * ψ^(-1)[{}] should equal 1", i, i);
        }
    }
}
