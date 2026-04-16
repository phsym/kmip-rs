#[cfg(feature = "arbitrary")]
mod setup;

#[cfg(all(feature = "arbitrary", feature = "_integration_tests"))]
#[cfg(test)]
mod tests {
    use super::*;

    use kmip::{
        CreateRequestPayload, ObjectType, ProtocolVersion, RequestMessage, RequestPayload,
        TemplateAttribute,
    };

    #[test]
    fn fuzz() {
        use arbitrary::Arbitrary;
        use rand::prelude::*;
        let mut client = setup::new_client();
        let mut data = vec![0u8; 20_000_000];
        rand::thread_rng().fill_bytes(&mut data);
        let unstructured = arbitrary::Unstructured::new(&data);
        let msg = RequestMessage::arbitrary_take_rest(unstructured).unwrap();

        client.roundtrip(&msg).unwrap();
    }

    #[test]
    fn fuzz_payload() {
        use arbitrary::Arbitrary;
        use rand::prelude::*;
        let mut client = setup::new_client();
        let mut data = vec![0u8; 20_000_000];
        rand::thread_rng().fill_bytes(&mut data);
        let unstructured = arbitrary::Unstructured::new(&data);
        let pl = RequestPayload::arbitrary_take_rest(unstructured).unwrap();
        let msg = RequestMessage::new(ProtocolVersion::V1_0, pl);

        client.roundtrip(&msg).unwrap();
    }

    #[test]
    fn fuzz_create() {
        use arbitrary::Arbitrary;
        use rand::prelude::*;
        let mut client = setup::new_client();
        let mut data = vec![0u8; 20_000_000];
        rand::thread_rng().fill_bytes(&mut data);
        let unstructured = arbitrary::Unstructured::new(&data);
        // let msg = RequestMessage::arbitrary_take_rest(unstructured).unwrap();
        let msg = RequestMessage::new(
            ProtocolVersion::V1_0,
            CreateRequestPayload {
                object_type: ObjectType::SymmetricKey,
                attributes: TemplateAttribute::new(
                    Arbitrary::arbitrary_take_rest(unstructured).unwrap(),
                ), // attributes: Arbitrary::arbitrary_take_rest(unstructured).unwrap(),
            }, // Arbitrary::arbitrary_take_rest(unstructured).unwrap(),
        );

        client.roundtrip(&msg).unwrap();
    }
}
