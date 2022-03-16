use ch1::{hex2bin};
use ch3::{break_xor_byte};

use std::io::{BufRead,BufReader};
use std::fs::File;

fn main() {
    let reader = BufReader::new(
                    File::open("4.txt").expect("failed to open file")
                );

    let mut haystack = Vec::new();
    for line in reader.lines(){
        let line_bin = hex2bin( line.unwrap().as_bytes()).unwrap();
        let (score, key, decrypt) =  break_xor_byte( line_bin.as_slice() );
        haystack.push( (score, key, decrypt ) )
    }

    haystack.sort_by_key( |k| k.0 );
    haystack.reverse();

    let (_score, key, decrypt) = haystack.remove(0);

    println!("{} {}", key, String::from_utf8_lossy( decrypt.as_slice() ));
}
