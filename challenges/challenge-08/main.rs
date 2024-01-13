// The sections that are commented out were part of the converter that
// ""encrypts"" what it reads from stdin. The whole encryption scheme is an
// absolute joke, but the fact that the only implementation you get to look at
// is written in the most obscure programming language ever should make it
// somewhat difficult to reverse ...

use std::{
    collections::HashMap,
    io::{self, Read},
};

use rand::Rng;

type KeyComponent = [u8; 3];
type Key = [KeyComponent; 4];
type Hash = [u8; 8];

fn mix(mut input: Hash) -> Hash {
    for i in 0..input.len() {
        input[i] = input[i].wrapping_add(input[(i + 1) % 8]).wrapping_add(69);
    }
    input
}

fn shift(mut input: Hash) -> Hash {
    input[0] = input[0].rotate_left(1);
    input[5] = input[5].rotate_right(3);
    input
}

fn hash(input: &[u8; 3]) -> Hash {
    let mut expanded_input = [input[0], 42, input[1], input[2], 0xDE, 0xAD, 0xBE, 0xEF];

    for _ in 0..23 {
        expanded_input = mix(expanded_input);
        expanded_input = shift(expanded_input);
    }

    expanded_input
}

fn derive_key(key: &Key) -> [u64; 4] {
    key.iter()
        .map(hash)
        .map(u64::from_le_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn encrypt_u64(data: u64, mut derived_key_component: u64) -> (u64, u64) {
    let encrypted_data = data.wrapping_add(derived_key_component);
    derived_key_component = derived_key_component.rotate_right(16).wrapping_add(data).rotate_right(16).wrapping_sub(data);
    (encrypted_data, derived_key_component)
}

fn decrypt_u64(data: u64, mut derived_key_component: u64) -> (u64, u64) {
    let decrypted_data = data.wrapping_sub(derived_key_component);
    derived_key_component = derived_key_component.rotate_right(16).wrapping_add(decrypted_data).rotate_right(16).wrapping_sub(decrypted_data);
    (decrypted_data, derived_key_component)
}

fn encrypt(data: &[u64]) -> (Vec<u64>, Key, [u64; 4]) {
    let mut rng = rand::thread_rng();
    let key: Key = rng.gen();
    let mut derived_key: [u64; 4] = derive_key(&key);
    let initial_derived_key = derived_key;
    let mut prev_val = 0;
    let encrypted_data = data
        .iter()
        .enumerate()
        .map(|(num, value)| {
            let delta_val = value.wrapping_sub(prev_val);
            prev_val = *value;
            let derived_key_component = &mut derived_key[num % derived_key.len()];
            let (encrypted_delta_val, new_derived_key_component) = encrypt_u64(delta_val, *derived_key_component);
            *derived_key_component = new_derived_key_component;
            encrypted_delta_val
        })
        .collect();
    let checksum: [u64; 4] = initial_derived_key
        .iter()
        .map(|value| {
            let delta_val = value.wrapping_sub(prev_val);
            prev_val = *value;
            delta_val
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    (encrypted_data, key, checksum)
}

fn decrypt(data: &[u64], key: &Key, checksum: &[u64; 4]) -> Vec<u64> {
    let mut derived_key: [u64; 4] = derive_key(&key);
    let initial_derived_key = derived_key;
    let mut prev_val = 0;
    let decrypted_data = data
        .iter()
        .enumerate()
        .map(|(num, encrypted_delta_value)| {
            let derived_key_component = &mut derived_key[num % derived_key.len()];
            let (delta_val, new_derived_key_component) = decrypt_u64(*encrypted_delta_value, *derived_key_component);
            eprintln!("decrypting {:?} with {:?} yields {:?} and {:?}", encrypted_delta_value.to_le_bytes(), derived_key_component.to_le_bytes(), delta_val.to_le_bytes(), new_derived_key_component.to_le_bytes());
            let value = delta_val.wrapping_add(prev_val);
            prev_val = value;
            *derived_key_component = new_derived_key_component;
            value
        })
        .collect();
    let decrypted_checksum: [u64; 4] = checksum
        .iter()
        .map(|delta_val| {
            let value = delta_val.wrapping_add(prev_val);
            prev_val = value;
            value
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    assert_eq!(decrypted_checksum, initial_derived_key);
    decrypted_data
}

fn i32_to_u8_array(i: i32) -> [u8; 3] {
    i.to_le_bytes()[..3].try_into().unwrap()
}

fn get_key_from_checksum(
    checksum: &[u64; 4],
    mut prev_val: u64,
    hash_to_input: &HashMap<u64, [u8; 3]>,
) -> Option<Key> {
    checksum
        .iter()
        .map(|delta_checksum_component| {
            let checksum_component = delta_checksum_component.wrapping_add(prev_val);
            prev_val = checksum_component;
            hash_to_input.get(&checksum_component)
        })
        .collect::<Option<Vec<_>>>()
        .map(|vec| {
            vec.iter()
                .map(|&x| *x)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
}

fn crack(
    checksum: &[u64; 4],
    hash_to_input: &HashMap<u64, [u8; 3]>,
) -> Key {
    let mut key_filter = hash_to_input.iter().filter_map(|(hash, _)| {
        get_key_from_checksum(checksum,hash.wrapping_sub(checksum[0]), hash_to_input)
    });
    let key = key_filter.next().unwrap();
    assert_eq!(key_filter.next(), None, "oh no, we've got a collision");
    key
}

const BLOCK_SIZE: usize = 32;

fn main() {
    /*let mut data = Vec::new();
    io::stdin().read_to_end(&mut data).unwrap();
    data.resize_with(data.len().div_ceil(BLOCK_SIZE) * BLOCK_SIZE, || 0x42);
    let data: Vec<u64> = data
        .chunks(8)
        .map(|slice| u64::from_le_bytes(slice.try_into().unwrap()))
        .collect();
    let (encrypted_data, key, checksum) = encrypt(&data);

    let decrypted_data = decrypt(&encrypted_data, &key, &checksum);
    assert_eq!(data, decrypted_data);
    eprintln!("decryption successful");*/

    let hash_to_input: HashMap<u64, [u8; 3]> = (0..0x1000000)
        .map(|input: i32| {
            let input_array = i32_to_u8_array(input);
            (u64::from_le_bytes(hash(&input_array)), input_array)
        })
        .collect();
    assert_eq!(hash_to_input.len(), 0x1000000);
    eprintln!("hash table generated");

    /*let cracked_key = crack(&checksum, &hash_to_input);
    assert_eq!(key, cracked_key);

    let cracked_data = decrypt(&encrypted_data, &cracked_key, &checksum);
    assert_eq!(data, cracked_data);

    eprintln!("crack successful");

    // here you can see what happens to your code when you debug for too long and don't clean up afterwards
    eprintln!("key: {}", key.iter().flat_map(|x| x.iter()).map(|x| format!("{:02x}", x)).collect::<String>());
    eprintln!("key: {}", key.iter().flat_map(|x| x.iter()).map(|x| format!("{} ", x)).collect::<String>());
    eprintln!("derived key: {:?}", derive_key(&key));
    eprintln!("derived key bytes: {:?}", key.iter().map(hash).collect::<Vec<_>>());
    eprintln!("derived key0 bits: {:032b}", u64::from_le_bytes(hash(&key[0])));
    eprintln!("checksum: {:?}", checksum);

    
    for (byte_num, byte) in encrypted_data.iter().flat_map(|x| x.to_le_bytes()).chain(checksum.iter().flat_map(|x| x.to_le_bytes())).enumerate() {
        println!("push {}", byte);
        if (byte_num % BLOCK_SIZE) == (BLOCK_SIZE - 1) {
            println!("push GENERATED_LABEL{}\npush DECRYPT_CHUNK\njmp\nGENERATED_LABEL{}:", byte_num / 32, byte_num / 32);
        }
    }
    // (that also generates a """"subroutine call"""" after the checksum because I got lazy/frustrated and manually removed it from the output)
    */

    // when I realised that I need to submit a solution I quickly cobbled this together:
    let to_be_cracked = vec![147, 234, 223, 192, 116, 184, 31, 185, 252, 78, 245, 60, 214, 223, 103, 204, 123, 144, 152, 118, 66, 255, 170, 138, 41, 18, 135, 141, 33, 145, 12, 177];
    // ^ that is just the "checksum" which is pushed after the ""encrypted"" data
    // (why, oh why, did I decide to use arrays for everything ;_;)
    eprintln!("cracked key: {}", crack(to_be_cracked.chunks(8).map(|x| u64::from_le_bytes(x.try_into().unwrap())).collect::<Vec<_>>().as_slice().try_into().unwrap(),&hash_to_input).iter().flat_map(|x| x.iter()).map(|x| format!("{:02x}", x)).collect::<String>());
}
