use ch1::{hex2bin, bin2hex};
use ch2::{fixed_xor};

/*
Write a function that takes two equal-length buffers and produces their XOR combination.
If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965

... should produce:

746865206b696420646f6e277420706c6179
*/

fn main() {
    let x0 = String::from("1c0111001f010100061a024b53535009181c");
    let x1 = String::from("686974207468652062756c6c277320657965");

    let x0_bin = hex2bin( x0.as_bytes() ).unwrap();
    println!("x0_bin: {:x?}", x0_bin);
    let x1_bin = hex2bin( x1.as_bytes() ).unwrap();
    println!("x1_bin: {:x?}", x1_bin);

    let xor = fixed_xor( x0_bin.as_slice(), x1_bin.as_slice() ).unwrap();
    let xor_hex = bin2hex( xor.as_slice() ).unwrap() ;
    println!("xor_hex: {}",xor_hex);
    assert_eq!( xor_hex, String::from("746865206b696420646f6e277420706c6179"));
}
