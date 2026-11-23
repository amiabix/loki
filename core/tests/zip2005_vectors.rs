use loki_poc::zip2005::frost_viewing_key;
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/zip2005_use_qsk.json");

fn bytes32(v: &Value, name: &str) -> [u8; 32] {
    hex::decode(v[name].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn zip2005_matches_published_use_qsk_vectors() {
    let data: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(data["qk_context"], "Zcash ZIP 2005 qk-derivation v1");

    let vectors = data["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 8, "expected the 8 published vectors");

    for (i, v) in vectors.iter().enumerate() {
        let ak = bytes32(v, "ak");
        let sk = bytes32(v, "sk");
        let want_fvk = hex::decode(v["fvk"].as_str().unwrap()).unwrap();

        let fvk = frost_viewing_key(&ak, &sk).expect("valid FVK");
        let got = fvk.to_bytes();

        assert_eq!(hex::encode(got), hex::encode(&want_fvk), "vector {i}: FVK");
        assert_eq!(&got[..32], &ak, "vector {i}: ak preserved");
        assert_eq!(&got[32..64], bytes32(v, "nk"), "vector {i}: nk");
        assert_eq!(&got[64..96], bytes32(v, "rivk_ext"), "vector {i}: rivk");
    }
}
