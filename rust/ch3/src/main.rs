use ch1::{hex2bin, bin2hex};
use ch3::{break_xor_byte};
/*
 The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score. 
*/

fn main() {
    let input_hex = String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let input_bin = hex2bin( input_hex.as_bytes()).unwrap();
    let (_score, key, decrypt) = break_xor_byte( input_bin.as_slice() );
    println!("key: {:?} {:?}",key, decrypt);
    println!("{}",String::from_utf8_lossy(decrypt.as_slice() ));
}
