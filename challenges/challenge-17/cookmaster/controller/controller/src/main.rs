use ecsimple::group::ecc_get_curve_group;
use ecsimple::keys::ECPrivateKey;
use ecsimple::randop::update_randop;
use futures_util::{SinkExt, StreamExt};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socketcan::{tokio::CanFdSocket, CanAnyFrame, Frame};
use socketcan::{CanFdFrame, EmbeddedFrame, ExtendedId};
use std::collections::HashMap;
use std::env;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::sleep;

const MSGID_TEMP: u32 = 0x12;
const MSGID_ADD: u32 = 0x13;
const MSGID_MIX: u32 = 0x14;
const MSGID_HEAT: u32 = 0x15;
const MSGID_WAIT: u32 = 0x16;
const MSGID_START: u32 = 0x20;
const MSGID_RESET: u32 = 0x21;

const RS_LENGTH: usize = 14;
const SIGNATURE_LENGTH: usize = RS_LENGTH * 2;
const MAX_SIGNED_MESSAGE: usize = 64 - SIGNATURE_LENGTH;

type AmountInGrams = u16;
type Strength = u8;
type Seconds = u16;
type Degrees = u16;

#[derive(Clone, Serialize, Deserialize, Debug)]
enum Ingredient {
    Custom(String),
    Tomato,
    Carrot,
    Celery,
    Onion,
    Garlic,
    Sugar,
    OliveOil,
    Salt,
    BlackPepper,
}

impl Into<u8> for &Ingredient {
    fn into(self) -> u8 {
        match self {
            Ingredient::Custom(_) => 0,
            Ingredient::Tomato => 1,
            Ingredient::Carrot => 2,
            Ingredient::Celery => 3,
            Ingredient::Onion => 4,
            Ingredient::Garlic => 5,
            Ingredient::Sugar => 6,
            Ingredient::OliveOil => 7,
            Ingredient::Salt => 8,
            Ingredient::BlackPepper => 9,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
enum RecipeStep {
    Add(Ingredient, AmountInGrams),
    Mix(Strength, Seconds),
    Heat(Degrees, Seconds),
    Wait(Seconds),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let iface = env::var("CAN_IF")
        .expect("No SocketCAN interface specified with CAN_IF env");
    let recipe_file = env::var("RECIPE_PATH")
        .expect("No RECIPE_PATH env specified for recipe.json");
    let flag_file =
        env::var("FLAG_PATH").expect("No FLAG_PATH env specified");

    let mut recipe_map: HashMap<String, Vec<RecipeStep>> = {
        let mut f = File::open(&recipe_file).await?;
        let mut json = String::new();
        f.read_to_string(&mut json).await?;
        serde_json::from_str(&json)?
    };

    {
        let mut f = File::open(&flag_file).await?;
        let mut flag = String::new();
        f.read_to_string(&mut flag).await?;

        let steps: Vec<_> = flag
            .as_bytes()
            .chunks(5)
            .enumerate()
            .map(|(i, s)| {
                let string = String::from_utf8(s.to_vec()).unwrap();
                let ingredient = Ingredient::Custom(string);
                RecipeStep::Add(ingredient, i as u16)
            })
            .collect();
        recipe_map.insert("secret sauce".to_owned(), steps);
    }

    // Initialize ECDSA key/read it from file
    let private_key;
    let verifying_key;
    let group = ecc_get_curve_group("secp112r1").unwrap();
    let ossl_group =
        EcGroup::from_curve_name(openssl::nid::Nid::SECP112R1)?;
    if let Ok(v) = env::var("EC_SKEY") {
        if let Ok(mut f) = File::open(&v).await {
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).await?;

            let ossl_key = EcKey::private_key_from_pem(&buf)?;
            let ossl_key_der = ossl_key.private_key_to_der()?;
            private_key = tokio::task::spawn_blocking(move || {
                ECPrivateKey::from_der(&ossl_key_der).unwrap()
            })
            .await
            .unwrap();
            verifying_key = EcKey::from_public_key(
                &ossl_group,
                ossl_key.public_key(),
            )?;
        } else {
            private_key = tokio::task::spawn_blocking(move || {
                ECPrivateKey::generate(&group)
            })
            .await?;

            let skey = private_key.clone();
            let der = tokio::task::spawn_blocking(move || {
                skey.to_der("uncompressed", "").unwrap()
            })
            .await?;
            let ossl_key = EcKey::private_key_from_der(&der)?;
            verifying_key = EcKey::from_public_key(
                &ossl_group,
                ossl_key.public_key(),
            )?;
            let data = ossl_key.private_key_to_pem()?;
            let mut f = File::create(&v).await?;
            f.write_all(&data).await?;
        }
    } else {
        private_key = tokio::task::spawn_blocking(move || {
            ECPrivateKey::generate(&group)
        })
        .await?;
        let skey = private_key.clone();
        let der = tokio::task::spawn_blocking(move || {
            skey.to_der("uncompressed", "").unwrap()
        })
        .await?;
        let ossl_key = EcKey::private_key_from_der(&der)?;
        verifying_key = EcKey::from_public_key(
            &ossl_group,
            ossl_key.public_key(),
        )?;
    }

    let (mut can_tx, mut can_rx) = CanFdSocket::open(&iface)?.split();
    println!("Reading on {}", iface);

    // Initialize random generator
    let (rand_reset_tx, mut rand_reset_rx) = mpsc::channel(1);
    let (rand_tx, mut rand_rx) = mpsc::channel(5);
    rand_reset_tx.send(()).await.unwrap();

    tokio::spawn(async move {
        let mut seed = 0u64;
        let mut counter = 0;

        loop {
            select! {
                Some(_) = rand_reset_rx.recv() => {
                    seed = 0;
                    counter = 0;
                }
                Some(update) = rand_rx.recv() => {
                    seed = seed.wrapping_add(update);
                    counter += 1;

                    if counter == 5 {
                        //println!("Resetting randgen: {}", seed);
                        let rng = ChaCha8Rng::seed_from_u64(seed);
                        update_randop(rng).await;
                    }
                }
                else => break,
            }
        }
    });

    // Recipe processing
    let (recipe_tx, mut recipe_rx): (
        Sender<String>,
        Receiver<String>,
    ) = mpsc::channel(5);
    tokio::spawn(async move {
        while let Some(recipe_name) = recipe_rx.recv().await {
            let steps = match recipe_map.get(recipe_name.as_str()) {
                None => continue,
                Some(s) => s,
            };

            let mut data = Vec::with_capacity(MAX_SIGNED_MESSAGE);
            let mut frame_data = Vec::with_capacity(64);
            for step in steps {
                data.clear();
                frame_data.clear();

                let msg_id = match step {
                    RecipeStep::Add(ingredient, grams) => {
                        data.push(ingredient.into());
                        data.extend_from_slice(&grams.to_le_bytes());

                        // If we have a custom ingredient, append the
                        // name at the end of the message (limited to
                        // the first 30 characters).
                        if let Ingredient::Custom(name) = ingredient {
                            let name_bytes = name.as_bytes();
                            let max = name_bytes.len().min(30);
                            data.extend_from_slice(&name_bytes[..max]);
                        }

                        MSGID_ADD
                    }
                    RecipeStep::Mix(strength, seconds) => {
                        data.push(*strength);
                        data.extend_from_slice(&seconds.to_le_bytes());
                        MSGID_MIX
                    }
                    RecipeStep::Heat(degrees, seconds) => {
                        data.extend_from_slice(&degrees.to_le_bytes());
                        data.extend_from_slice(&seconds.to_le_bytes());
                        MSGID_HEAT
                    }
                    RecipeStep::Wait(seconds) => {
                        data.extend_from_slice(&seconds.to_le_bytes());
                        MSGID_WAIT
                    }
                };

                let mut hash = Sha256::new();
                hash.update(&data);
                let digest = hash.finalize();
                let skey = private_key.clone();
                let sig = tokio::task::spawn_blocking(move || {
                    skey.sign_base(&digest).unwrap()
                })
                .await
                .unwrap();

                frame_data.extend(sig.r.to_bytes_be().1);
                frame_data.extend(sig.s.to_bytes_be().1);
                frame_data.extend(&data);

                let mid = ExtendedId::new(msg_id).unwrap();
                if let Some(f) = CanFdFrame::new(mid, &frame_data) {
                    can_tx.send(f).await.unwrap();
                }

                match step {
                    RecipeStep::Mix(_, seconds)
                    | RecipeStep::Heat(_, seconds)
                    | RecipeStep::Wait(seconds) => {
                        sleep(Duration::from_secs(*seconds as u64))
                            .await
                    }
                    _ => sleep(Duration::from_secs(1)).await,
                }
            }
        }
    });

    // Frame processing
    let (frame_tx, mut frame_rx) = mpsc::channel(5);
    tokio::spawn(async move {
        while let Some(any_frame) = frame_rx.recv().await {
            let (msg_id, mut data): (_, Vec<_>) = match any_frame {
                CanAnyFrame::Fd(frame) => {
                    (frame.raw_id(), frame.data().into())
                }
                CanAnyFrame::Normal(frame) => {
                    (frame.raw_id(), frame.data().into())
                }
                CanAnyFrame::Remote(frame) => {
                    (frame.raw_id(), frame.data().into())
                }
                CanAnyFrame::Error(frame) => {
                    (frame.raw_id(), frame.data().into())
                }
            };

            match msg_id {
                MSGID_START => {
                    if data.len() < SIGNATURE_LENGTH + 1 {
                        continue;
                    }
                    let r_slice = &data[..RS_LENGTH];
                    let s_slice = &data[RS_LENGTH..SIGNATURE_LENGTH];
                    let r = match BigNum::from_slice(r_slice) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let s = match BigNum::from_slice(s_slice) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let sig = EcdsaSig::from_private_components(r, s);
                    let sig = match sig {
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    let payload = data.split_off(SIGNATURE_LENGTH);
                    let mut hash = Sha256::new();
                    hash.update(&payload);
                    let digest = hash.finalize();

                    let result = sig.verify(&digest, &verifying_key);
                    match result {
                        Ok(true) => (),
                        _ => continue,
                    }

                    if let Ok(s) = String::from_utf8(payload) {
                        recipe_tx.send(s).await.unwrap();
                    }
                }
                MSGID_RESET => rand_reset_tx.send(()).await.unwrap(),
                MSGID_TEMP => {
                    let buf: Result<[u8; 8], _> = data.try_into();
                    if let Ok(b) = buf {
                        let val = u64::from_le_bytes(b);
                        rand_tx.send(val).await.unwrap();
                    }
                }
                _ => println!("got unknown msg_id 0x{:x}", msg_id),
            }
        }
    });

    while let Some(res) = can_rx.next().await {
        match res {
            Ok(frame) => frame_tx.send(frame).await?,
            Err(err) => eprintln!("{}", err),
        }
    }

    Ok(())
}
