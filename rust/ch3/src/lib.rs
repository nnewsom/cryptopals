use std::collections::HashMap;

pub fn byte_xor( input: &[u8], key_byte: u8 ) -> Vec<u8> {
    let mut output = Vec::with_capacity( input.len() );
    for x in input {
        output.push( x ^ key_byte )
    }
    output
}

fn frequency_score( input: &[u8] ) -> u64 {
    let mut output = 0;
    // the freqs used to be floating point, but apparently
    // there isn't an Ord for f64, so sorting later will be a
    // pain. since it's just the sum, converted to full 
    // numbers and it should work the same
    let freq_table = HashMap::from( [
        (b'a', 0651738), (b'b', 0124248), (b'c', 0217339),
        (b'd', 0349835), (b'e', 1041442), (b'f', 0197881),
        (b'g', 0158610), (b'h', 0492888), (b'i', 0558094),
        (b'j', 0009033), (b'k', 0050529), (b'l', 0331490),
        (b'm', 0202124), (b'n', 0564513), (b'o', 0596302),
        (b'p', 0137645), (b'q', 0008606), (b'r', 0497563),
        (b's', 0515760), (b't', 0729357), (b'u', 0225134),
        (b'v', 0082903), (b'w', 0171272), (b'x', 0013692),
        (b'y', 0145984), (b'z', 0007836), (b' ', 1918182) 
    ]);

    for byte in input {
        match byte {
            65..=90 => {
                let lower = byte+32;
                output += match freq_table.get( &lower ) {
                    Some(freq) => freq,
                    None => &0u64
                };
            },
            _ => {
                output += match freq_table.get( byte ) {
                    Some(freq) => freq,
                    None => &0u64
                };
            }
        };
    }

    return output
}

pub fn break_xor_byte( input: &[u8] ) -> (u64, u8, Vec<u8>) {
    let mut attempts = Vec::new();
    for i in 0..=255 {
        let xord = byte_xor( input, i );
        let score = frequency_score( xord.as_slice() );
        attempts.push( (score, i, xord) );
    }
    
    // sort by score in reverse so top score is first ele
    attempts.sort_by_key( |k| k.0 );
    attempts.reverse();

    // tuple of score,key,decrypt
    let best_attempt = attempts.remove(0);

    best_attempt
}
