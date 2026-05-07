#[cfg(feature = "_integration_tests")]
mod setup;

#[cfg(feature = "_integration_tests")]
#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Duration;
    use kmip::{
        CryptographicUsageMask, RequestMessage, Tags,
        attributes::{Attribute, AttributeName, CryptographicLength},
        client::BatchResultExt,
        enums::{
            BatchErrorContinuationOption, BlockCipherMode, CertificateType, CryptographicAlgorithm,
            LinkType, NameType, ObjectType, RecommendedCurve, ResultReason, ResultStatus,
            SecretDataType, State,
        },
        interop::{FormatEcPrivate, FormatEcPublic, FormatRsaPrivate, FormatRsaPublic},
        payloads::{
            CreateRequestPayload, DecryptRequestPayload, EncryptRequestPayload,
            LocateRequestPayload, QueryRequestPayload, RequestPayload,
        },
        types::{CryptographicParameters, Name, ProtocolVersion, TemplateAttribute},
    };
    use ttlv::{MaybeKnownTag, Struct, TTLV, Value};

    #[test]
    fn batch_transaction() {
        let mut client = setup::new_client();
        let mut msg = RequestMessage::new_batched(
            ProtocolVersion::V1_0,
            [
                RequestPayload::new(CreateRequestPayload {
                    object_type: ObjectType::SymmetricKey,
                    attributes: TemplateAttribute::new(vec![
                        Attribute::new(Name {
                            name_value: "K-1".into(),
                            name_type: NameType::UninterpretedTextString,
                        }),
                        Attribute::new(CryptographicAlgorithm::AES),
                        Attribute::new(CryptographicLength(128)),
                        Attribute::new(
                            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                        ),
                    ]),
                }),
                RequestPayload::new(CreateRequestPayload {
                    object_type: ObjectType::SymmetricKey,
                    attributes: TemplateAttribute::new(vec![Attribute::new(Name {
                        name_value: "K-2".into(),
                        name_type: NameType::UninterpretedTextString,
                    })]),
                }),
                RequestPayload::new(CreateRequestPayload {
                    object_type: ObjectType::SymmetricKey,
                    attributes: TemplateAttribute::new(vec![
                        Attribute::new(Name {
                            name_value: "K-3".into(),
                            name_type: NameType::UninterpretedTextString,
                        }),
                        Attribute::new(CryptographicAlgorithm::AES),
                        Attribute::new(CryptographicLength(128)),
                        Attribute::new(
                            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                        ),
                    ]),
                }),
            ],
        )
        .unwrap();
        msg.header.batch_error_continuation_option =
            Some(kmip::enums::BatchErrorContinuationOption::Continue);

        client.roundtrip(msg).unwrap();
    }

    #[test]
    fn rekey() {
        let mut client = setup::new_client();
        let key_id = client
            .create()
            .aes(
                256,
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            )
            .exec()
            .unwrap()
            .unique_identifier;

        client
            .rekey(key_id)
            .with_offset(Duration::days(1))
            .exec()
            .unwrap();
    }

    #[test]
    fn rekey_keypair() {
        let mut client = setup::new_client();
        let key_id = client
            .create_keypair()
            .rsa(
                2048,
                CryptographicUsageMask::Sign,
                CryptographicUsageMask::Verify,
            )
            .exec()
            .unwrap()
            .private_key_unique_identifier;

        let response = client
            .rekey_keypair(key_id)
            .with_offset(Duration::days(1))
            .exec()
            .unwrap();

        assert!(!response.private_key_unique_identifier.is_empty());
        assert!(!response.public_key_unique_identifier.is_empty());
        println!(
            "New Private Key ID: {:?}, New Public Key ID: {:?}",
            response.private_key_unique_identifier, response.public_key_unique_identifier
        );
    }

    // fn get_usage_allocation(client: &mut Client) {
    //     client.get_usage_allocation(RESOURCE_ID, 12).exec().unwrap();
    // }

    // fn obtain_lease(client: &mut Client) {
    //     client.obtain_lease(RESOURCE_ID).exec().unwrap();
    // }

    #[test]
    fn unsupported_op() {
        let mut client = setup::new_client();
        let msg = RequestMessage::new(
            ProtocolVersion::V1_0,
            RequestPayload::Unknown(
                0x80000001.into(),
                Struct(vec![TTLV {
                    tag: MaybeKnownTag::Known(Tags::UniqueIdentifier),
                    val: Value::TextString("1234567890".into()),
                }]),
            ),
        );
        let resp = client.roundtrip(msg).unwrap();
        assert_eq!(resp.batch_item.len(), 1);
        let bi = &resp.batch_item[0];
        assert_eq!(bi.result_status, ResultStatus::OperationFailed);
        assert_eq!(bi.result_reason, Some(ResultReason::GeneralFailure));
    }

    // fn archive(client: &mut Client) {
    //     client.archive(RESOURCE_ID).exec().unwrap();
    // }

    // fn recover(client: &mut Client) {
    //     client.recover(RESOURCE_ID).exec().unwrap();
    // }

    #[test]
    fn query() {
        let mut client = setup::new_client();
        client.query().all().exec().unwrap();
    }

    // fn revoke(client: &mut Client) {
    //     client
    //         .revoke(RESOURCE_ID)
    //         .with_revocation_reason_code(RevocationReasonCode::CessationOfOperation)
    //         .exec()
    //         .unwrap();
    // }

    // fn activate(client: &mut Client) {
    //     client.activate(RESOURCE_ID).exec().unwrap();
    // }

    // fn delete_attribute(client: &mut Client) {
    //     client
    //         .delete_attribute(RESOURCE_ID, AttributeName::Unknown("x-foo3".into()))
    //         .exec()
    //         .unwrap();
    // }

    // fn modify_attribute(client: &mut Client) {
    //     client
    //         .modify_attribute(
    //             RESOURCE_ID,
    //             AttributeValue::Unknown {
    //                 name: "x-foo3".into(),
    //                 value: ttlv::Value::TextString("baz".into()),
    //             },
    //         )
    //         .exec()
    //         .unwrap();
    // }

    // fn add_attribute(client: &mut Client) {
    //     client
    //         .add_attribute(
    //             RESOURCE_ID,
    //             AttributeValue::Link(Link {
    //                 link_type: LinkType::PublicKeyLink,
    //                 linked_object_identifier: "abcdef".into(),
    //             }),
    //         )
    //         .exec()
    //         .unwrap();
    // }

    // fn destroy(client: &mut Client) {
    //     client.destroy(RESOURCE_ID).exec().unwrap();
    // }

    #[test]
    fn register_certificate() {
        let mut client = setup::new_client();
        let crt = rcgen::generate_simple_self_signed(["hello.world".to_string()]).unwrap();

        client
            .register()
            .certificate(CertificateType::X509, crt.cert.der().to_vec())
            .with_name("Test-PH-Certificate")
            .exec()
            .unwrap();
    }

    #[test]
    fn register_secret() {
        let mut client = setup::new_client();
        client
            .register()
            .secret(SecretDataType::Password, "hello world")
            .with_name("Test-PH-Secret")
            .exec()
            .unwrap();
    }

    #[test]
    fn register_aes() {
        let mut client = setup::new_client();
        let key = &b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"[..];
        client
            .register()
            .symmetric_key(
                key,
                CryptographicAlgorithm::AES,
                kmip::interop::FormatSymmetric::Raw,
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            )
            .unwrap()
            .exec()
            .unwrap();
    }

    #[test]
    fn register_pkcs8_rsa() {
        let mut client = setup::new_client();

        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();

        client
            .register()
            .private_key(
                key,
                FormatRsaPrivate::PKCS8,
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            )
            .unwrap()
            .exec()
            .unwrap();
    }

    #[test]
    fn register_pkcs1_rsa() {
        let mut client = setup::new_client();
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();

        client
            .register()
            .private_key(
                key,
                FormatRsaPrivate::PKCS1,
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            )
            .unwrap()
            .exec()
            .unwrap();
    }

    #[test]
    fn register_transparent_rsa() {
        let mut client = setup::new_client();
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();

        // let key = openssl::rsa::Rsa::generate(2048).unwrap();
        client
            .register()
            .private_key(
                key,
                FormatRsaPrivate::Transparent,
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            )
            .unwrap()
            .with_name("Test PH RSA")
            .exec()
            .unwrap();
    }

    #[test]
    fn register_pkcs8_ecdsa() {
        let mut client = setup::new_client();
        let key = p256::SecretKey::random(&mut rand::thread_rng());
        client
            .register()
            .private_key(
                key,
                FormatEcPrivate::PKCS8,
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            )
            .unwrap()
            .exec()
            .unwrap();
    }

    #[test]
    fn register_sec1_ecdsa() {
        let mut client = setup::new_client();
        let key = p256::SecretKey::random(&mut rand::thread_rng());
        client
            .register()
            .private_key(
                key,
                FormatEcPrivate::SEC1,
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            )
            .unwrap()
            .exec()
            .unwrap();
    }

    #[test]
    fn register_transparent_ecdsa() {
        let mut client = setup::new_client();
        let key = p256::SecretKey::random(&mut rand::thread_rng());
        client
            .register()
            .private_key(
                key,
                FormatEcPrivate::Transparent,
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            )
            .unwrap()
            .exec()
            .unwrap();
    }

    #[test]
    fn register_transparent_ecdsa_public() {
        let mut client = setup::new_client();
        let key = p256::SecretKey::random(&mut rand::thread_rng());
        client
            .register()
            .public_key(
                key.public_key(),
                FormatEcPublic::Transparent,
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            )
            .unwrap()
            .exec()
            .unwrap();
    }

    // fn get(client: &mut Client) {
    //     client
    //         .get(RESOURCE_ID)
    //         .with_key_format(kmip::KeyFormatType::TransparentRSAPrivateKey)
    //         .exec()
    //         .unwrap();
    // }

    // fn get_attributes(client: &mut Client) {
    //     client
    //         .get_attributes(RESOURCE_ID)
    //         .with_attribute(AttributeName::ObjectType)
    //         .exec()
    //         .unwrap();
    // }

    // fn get_attribute_list_with_placeholder(client: &mut Client) {
    //     let msg = RequestMessage::new_batched(
    //         ProtocolVersion::V1_0,
    //         vec![
    //             RequestPayload::new(kmip::CreateRequestPayload {
    //                 object_type: ObjectType::SymmetricKey,
    //                 attributes: TemplateAttribute::new(vec![
    //                     Attribute::new(kmip::AttributeValue::CryptographicAlgorithm(
    //                         kmip::CryptographicAlgorithm::AES,
    //                     )),
    //                     Attribute::new(kmip::AttributeValue::CryptographicLength(256)),
    //                     Attribute::new(kmip::AttributeValue::CryptographicUsageMask(
    //                         CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
    //                     )),
    //                 ]),
    //             }),
    //             RequestPayload::new(kmip::GetAttributeListRequestPayload {
    //                 unique_identifier: None,
    //             }),
    //         ],
    //     );

    //     request(client, msg);
    // }

    // fn get_attribute_list(client: &mut Client) {
    //     client.get_attribute_list(RESOURCE_ID).exec().unwrap();
    // }

    #[test]
    fn locate() {
        let mut client = setup::new_client();
        client.locate().exec().unwrap();
    }

    #[test]
    fn create() {
        let mut client = setup::new_client();
        client
            .create()
            .aes(
                256,
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            )
            .with_name("Test-PH-AES")
            .exec()
            .unwrap();
    }

    #[test]
    fn create_keypair_ecdsa() {
        let mut client = setup::new_client();
        client
            .create_keypair()
            .ecdsa(
                RecommendedCurve::P256,
                CryptographicUsageMask::Sign,
                CryptographicUsageMask::Verify,
            )
            .with_name("Test-PH-EC")
            .exec()
            .unwrap();
    }

    #[test]
    fn create_keypair_rsa() {
        let mut client = setup::new_client();
        client
            .create_keypair()
            .rsa(
                2048,
                CryptographicUsageMask::Sign,
                CryptographicUsageMask::Verify,
            )
            .with_name("Test-PH-RSA")
            .exec()
            .unwrap();
    }

    #[test]
    fn discover() {
        let mut client = setup::new_client();
        let msg = RequestMessage::new_batched(
            ProtocolVersion::V1_1,
            vec![
                RequestPayload::new(kmip::payloads::DiscoverVersionsRequestPayload {
                    protocol_version: vec![
                        kmip::types::ProtocolVersion {
                            protocol_version_major: 1,
                            protocol_version_minor: 4,
                        },
                        kmip::types::ProtocolVersion {
                            protocol_version_major: 1,
                            protocol_version_minor: 0,
                        },
                    ],
                }),
                RequestPayload::new(kmip::payloads::DiscoverVersionsRequestPayload {
                    protocol_version: vec![],
                }),
            ],
        )
        .unwrap();
        client.roundtrip(msg).unwrap();
    }

    #[test]
    fn set_link() {
        let mut client = setup::new_client();
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let privkey = client
            .register()
            .private_key(
                &key,
                FormatRsaPrivate::Transparent,
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            )
            .unwrap()
            .exec()
            .unwrap();

        let pubkey = client
            .register()
            .public_key(
                key.to_public_key(),
                FormatRsaPublic::Transparent,
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            )
            .unwrap()
            .with_link(LinkType::PrivateKeyLink, privkey.unique_identifier)
            .exec()
            .unwrap();

        let resp = client
            .get_attributes(pubkey.unique_identifier)
            .with_attribute(AttributeName::Link)
            .exec()
            .unwrap();
        println!("{resp:#?}");
    }

    #[test]
    fn set_link_ecdsa() {
        let mut client = setup::new_client();
        let key = p256::SecretKey::random(&mut rand::thread_rng());

        let privkey = client
            .register()
            .private_key(
                &key,
                FormatEcPrivate::Transparent,
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            )
            .unwrap()
            .exec()
            .unwrap();

        let pubkey = client
            .register()
            .public_key(
                key.public_key(),
                FormatEcPublic::Transparent,
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            )
            .unwrap()
            .with_link(LinkType::PrivateKeyLink, privkey.unique_identifier)
            .exec()
            .unwrap();

        let resp = client
            .get_attributes(pubkey.unique_identifier)
            .with_attribute(AttributeName::Link)
            .exec()
            .unwrap();
        println!("{resp:#?}");
    }

    #[test]
    fn encrypt_decrypt() {
        let mut client = setup::new_client();
        let key_id = client
            .create()
            .aes(
                256,
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            )
            .with_name("Test-Encrypt")
            .with_attribute(State::Active)
            .with_attribute(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCM),
                ..Default::default()
            })
            .exec()
            .unwrap()
            .unique_identifier;

        let resp = client
            .request(EncryptRequestPayload {
                unique_identifier: Some(key_id),
                data: Some(b"Hello World".into()),
                iv_counter_nonce: Some(b"abcdefghijkl".into()),
                correlation_value: None,
                cryptographic_parameters: None,
                final_indicator: None,
                init_indicator: None,
                authenticated_encryption_additional_data: Some("toto".into()),
            })
            .unwrap();

        client
            .request(DecryptRequestPayload {
                unique_identifier: Some(resp.unique_identifier),
                data: resp.data,
                iv_counter_nonce: resp.iv_counter_nonce,
                authenticated_encryption_tag: resp.authenticated_encryption_tag,
                authenticated_encryption_additional_data: Some("toto".into()),
                cryptographic_parameters: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            })
            .unwrap();
    }

    // // fn get_rsa(client: &mut Client) {
    // //     // let pkey = openssl::rsa::Rsa::generate(2048).unwrap();
    // //     let pkey = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    // //     let id = client
    // //         .register()
    // //         .private_key(
    // //             &pkey,
    // //             FormatRsaPrivate::Transparent,
    // //             CryptographicUsageMask::Sign,
    // //         )
    // //         .unwrap()
    // //         .exec()
    // //         .unwrap()
    // //         .unique_identifier;

    // //     let resp = client.get(id).exec().unwrap();

    // //     let pkey2 = resp
    // //         .private_key::<rsa::RsaPrivateKey>()
    // //         // .private_key::<openssl::rsa::Rsa<openssl::pkey::Private>>()
    // //         .unwrap();

    // //     // assert_eq!(
    // //     //     pkey.public_key_to_der().unwrap(),
    // //     //     pkey2.public_key_to_der().unwrap()
    // //     // );
    // //     assert_eq!(pkey, pkey2);
    // // }

    // // fn get_ecdsa(client: &mut Client) {
    // //     let pkey =
    // //         // openssl::ec::EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap())
    // //         //     .unwrap();
    // //         p256::SecretKey::random(&mut rand::thread_rng());
    // //     let id = client
    // //         .register()
    // //         .private_key(
    // //             &pkey,
    // //             FormatEcPrivate::Transparent,
    // //             CryptographicUsageMask::Sign,
    // //         )
    // //         .unwrap()
    // //         .exec()
    // //         .unwrap()
    // //         .unique_identifier;

    // //     let resp = client.get(id).exec().unwrap();

    // //     let pkey2 = resp
    // //         // .private_key::<openssl::ec::EcKey<openssl::pkey::Private>>()
    // //         .private_key::<p256::SecretKey>()
    // //         .unwrap();

    // //     // assert_eq!(
    // //     //     pkey.public_key_to_der().unwrap(),
    // //     //     pkey2.public_key_to_der().unwrap()
    // //     // );
    // //     assert_eq!(pkey, pkey2);
    // // }

    #[test]
    fn typed_batch() {
        let mut client = setup::new_client();
        let resp = client
            .batch((
                LocateRequestPayload::default(),
                QueryRequestPayload::default(),
            ))
            .unwrap();
        let _a = resp.0.unwrap();
        let _b = resp.1.unwrap();
    }

    #[test]
    fn typed_batch_builder() {
        let mut client = setup::new_client();
        let resp = client
            .create()
            .aes(
                256,
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            )
            .and_then(|c| c.activate(None))
            .and_then(|c| c.revoke(None))
            .and_then(|c| c.destroy(None))
            .exec_opt(BatchErrorContinuationOption::Stop)
            .flatten()
            .unwrap();
        let _a = resp.0;
        let _b = resp.1;
        let _c = resp.2;
        let _d = resp.3;
    }
}
