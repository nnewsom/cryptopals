use ch6::{hamming_distance, xor_key_lengths, recover_xor_key};
use ch5::{repeat_xor};
use ch1::{b64decode};

fn main() {
    let x1 = String::from("this is a test");
    let x2 = String::from("wokka wokka!!!");

    let distance = hamming_distance( x1.as_bytes() , x2.as_bytes() ).unwrap();
    assert!( distance == 37 );

    let encoded_data =  std::fs::read("6.txt").expect("failed to open file");
    let data = b64decode( &encoded_data ).unwrap();
    println!("decoded msg length: {}", data.len());

    let possible_kl = xor_key_lengths( data.as_slice() ).unwrap();
    println!("possible kl: {:?}", possible_kl);
    let kl = possible_kl[0];

    let key = recover_xor_key( data.as_slice(), kl ).unwrap();
    println!("key: '{}' {:?}",
                String::from_utf8_lossy( key.as_slice() ),
                key
            );

    let mut xdata = data.to_vec();
    repeat_xor( xdata.as_mut_slice(), key.as_slice() );
    println!("\n{}", String::from_utf8_lossy( xdata.as_slice() ));
}
