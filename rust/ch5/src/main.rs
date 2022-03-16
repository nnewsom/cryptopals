use ch1::{hex2bin, bin2hex};
use ch5::{repeat_xor};

fn main() {
    let mut x0 = String::from("Burning 'em, if you ain't quick and nimble");
    let mut x1 = String::from("I go crazy when I hear a cymbal");
    let k = String::from("ICE");
    
    let mut to_crypt = Vec::new();
    to_crypt.push( x0 );
    to_crypt.push( x1 );
    

    // String::as_bytes_mut is unsafe so lets find another way
    // let x0_crypt = repeat_xor( x0.as_bytes_mut(), k.as_bytes());
    for plaintext in &to_crypt {
        println!("{}",plaintext);
        let mut x0_bytes = plaintext.bytes().collect::<Vec<_>>();
        repeat_xor( x0_bytes.as_mut_slice() , k.as_bytes());
        let x0_xor_hex = bin2hex( x0_bytes.as_slice() ).unwrap();
        println!("{}",x0_xor_hex);

    }
    /* 

pretty sure the hex strings are wrong in the challenge page 
given example:
"Burning 'em, if you ain't quick and nimble" [42] should create hex digest length 82
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272 [75]
length is 75...not divisible by two or expected value; unlike what's generated above

    lets confirm
    */

    // modified by adding 0 on end to be proper mod 2 length
    x0 = String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263242727652720");
    // modified by adding 0 on end to be proper mod 2 length
    x1 = String::from("a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f0");
    let mut to_verify = Vec::from([ x0, x1 ]);
    for v0 in &to_verify {
        let mut v0_bin = hex2bin( v0.as_bytes() ).unwrap();
        repeat_xor( v0_bin.as_mut_slice(), k.as_bytes());
        let v0_xor = String::from_utf8_lossy( v0_bin.as_slice() );
        println!("{:?}\n{}",v0_bin, v0_xor);
    }
                
    /* confirmed given examples are incorrect */
    
}
