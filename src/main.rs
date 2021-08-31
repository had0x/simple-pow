use sha2::{Digest, Sha256};
use std::env;
use std::io::ErrorKind;

///main function, can throw io error.
fn main() -> Result<(), std::io::Error> {
    //get a list of arguments passed to our program
    let arguments: Vec<String> = env::args().collect();

    //println!("{:#?}", arguments);

    //check if we actualy got some args or nothing was provided
    //we should always get a first argument
    if arguments.len() == 1 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "Cannot continue, please provide a hex string
             for parsing.",
        ));
    }

    //define our hex string
    let hex_string = &arguments[1];

    //try to decode to hexadecimal
    let vec_u8 = hex::decode(hex_string);
    //handle decode process
    match vec_u8 {
        //decoding was ok, continue next steps
        Ok(result) => {
            //println!("hex u8 val: {:#?}", result);
            //get length of decoded bytes
            let vec_len = result.len();

            //use a guard for 64 byte length
            if vec_len != 64 {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "Cannot continue, please provide a valid 64 byte hex string.",
                ));
            }

            //generate all posible 4 byte prefixes and then start hashing
            //we have 4 bytes that we need to find as a prefix
            let bytes = 4;
            //get number of bits
            let num_bits: u8 = 8 * bytes;
            //create this max possible value using bit shifting (we're still in base 2 here so this should work)
            let max_number: u64 = 1 << num_bits;

            //println!("{:#?}", (max_number - 1).to_ne_bytes());
            // println!("{}", max_number - 1);

            //all possible combinations are actualy a number so just deconstruct to binary
            for elem in 0..max_number - 1 {
                //println!("{}", elem);

                //current element in bytes
                let binary: [u8; 8] = elem.to_ne_bytes();
                //current element trimmed
                let mut binary_trimmed: [u8; 4] = [0, 0, 0, 0];
                //let go of last 4 bytes because we dont need it so just clone using a range
                binary_trimmed.clone_from_slice(&binary[0..4]);
                //no we have all possible combinations of bytes in this slice

                //create a hash input from generated prefix
                let mut hash_input: Vec<u8> = binary_trimmed.to_owned().to_vec();
                //extend the hash input with original string as bytes
                hash_input.extend(hex_string.as_bytes());

                //create a new hasher
                let mut hasher = Sha256::new();

                //send the input to the hasher
                hasher.update(&hash_input);

                //close the hasher so we can get a result
                let hasher_result = hasher.finalize();

                //define the last two bytes we are looking for
                let compare1: u8 = 0xca;
                let compare2: u8 = 0xfe;

                //get the last two bytes from the hashing result
                let last_two_bytes: Vec<&u8> = hasher_result.iter().rev().take(2).collect();

                //rule to match on this hash
                if last_two_bytes[1] == &compare1 && last_two_bytes[0] == &compare2 {
                    //get a string representation on this hash
                    let string_hash = format!("{:x}", hasher_result);
                    //output to stdout and break loop
                    println!("{}", string_hash);
                    println!("{}", hex::encode(binary_trimmed));

                    break;
                    /*
                    if string_hash.starts_with("6681") {
                        println!("current num: {}", elem);
                        println!("{}", string_hash);
                        println!("{}", hex::encode(binary_trimmed));
                    }
                    */
                    // println!("{:x}", hasher_result);
                }

                // println!("{:#?}", binary_trimmed);
                //println!("{:#?}", hash_input);
            }
        }
        Err(_) => {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Invalid hex string.",
            ));
        }
    }

    return Ok(());
}
