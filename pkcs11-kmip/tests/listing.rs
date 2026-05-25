mod common;

use common::{first_slot, pkcs11};

#[test]
fn list_slots() {
    let pkcs = pkcs11();
    let slots = pkcs.get_all_slots().expect("get_all_slots");
    assert!(!slots.is_empty(), "expected at least one slot");
    for slot in &slots {
        let info = pkcs.get_slot_info(*slot).expect("get_slot_info");
        println!(
            "slot {slot}: manufacturer={} description={}",
            info.manufacturer_id(),
            info.slot_description()
        );
    }
}

#[test]
fn list_mechanisms() {
    let pkcs = pkcs11();
    let slot = first_slot();
    let mechs = pkcs.get_mechanism_list(slot).expect("get_mechanism_list");
    assert!(!mechs.is_empty(), "expected at least one mechanism");
    for mech in mechs {
        let info = pkcs
            .get_mechanism_info(slot, mech)
            .expect("get_mechanism_info");
        println!("mechanism : {mech}, info: {info:?}");
    }
}
