pub mod ch1;

use ch1::{hex2bin,b64encode, b64decode };
/*
challenge is to base64 hex encoded string
"'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'"
basically looking for
base64.b64encode( binascii.unhexlify( x ) )
b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
*/

fn main() {
    let test = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let bin = hex2bin( test.as_bytes() ).unwrap();
    println!("bin: {:x?}", bin);
    let unhex = String::from_utf8_lossy( bin.as_slice() );
    println!("unhex: {:?}", unhex);
    assert_eq!( unhex, String::from("I'm killing your brain like a poisonous mushroom"));
    let encoded = b64encode( unhex.as_bytes()).unwrap();
    let pretty_encoded = String::from_utf8_lossy( encoded.as_slice() );
    println!("encoded: {:?}", pretty_encoded);
    assert_eq!( pretty_encoded , String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"));
}
