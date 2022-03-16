use std::collections::HashMap;

#[derive(Debug)]
pub enum ConversionError {
    InvalidLength,
    InvalidInput(u8),
    InvalidIndex(u8)
}


/* for debug */
/*
use std::io::{stdin, stdout, Read,Write };
fn pause(){
    let mut stdout = std::io::stdout();
    stdout.write(b"Press enter to continue...").unwrap();
    stdout.flush().unwrap();
    std::io::stdin().read( &mut [0]).unwrap();
}
*/

pub fn hex2bin(  input: &[u8] ) -> Result< Vec<u8>, ConversionError>{
    let mut output = Vec::new();

    if input.len() % 2 != 0 {
        return Err( ConversionError::InvalidLength )
    }
    for pair in 0..(input.len()/2) {
        let mut byte = 0;
        for x in &input[ pair * 2 .. (pair+1) * 2] {
            let val = match x {
                b'a'..=b'f' => x - b'a' + 10,
                b'A'..=b'F' => x - b'A' + 10,
                b'0'..=b'9' => x - b'0',
                _ => return Err(ConversionError::InvalidInput( *x )),
            };
            byte = ( byte << 4 ) | val;
        }
        output.push( byte);
    }
    Ok(output)
}

pub fn bin2hex( input: &[u8] ) -> Result< String, ConversionError> {
    let mut output = String::new();

    for byte in input {
        output.push_str( format!("{:02x}", byte ).as_str() );
    }
    Ok(output)
}

pub fn base64encode( input: &[u8] ) -> Result< Vec<u8>, ConversionError> {
    let mut output = Vec::new();
    let table = [
        b'A',b'B',b'C',b'D',b'E',b'F',b'G',b'H',b'I',b'J',b'K',b'L',b'M',
        b'N',b'O',b'P',b'Q',b'R',b'S',b'T',b'U',b'V',b'W',b'X',b'Y',b'Z',
        b'a',b'b',b'c',b'd',b'e',b'f',b'g',b'h',b'i',b'j',b'k',b'l',b'm',
        b'n',b'o',b'p',b'q',b'r',b's',b't',b'u',b'v',b'w',b'x',b'y',b'z',
        b'0',b'1',b'2',b'3',b'4',b'5',b'6',b'7',b'8',b'9',b'+',b'/'
    ];
    let input_length = input.len();
    for idx in 0..( input_length /3 +1) {
        let end_idx = core::cmp::min( idx * 3 + 3, input_length );
        let block = &input[ idx * 3 .. end_idx ];
        let mut tripple = 0u32;

        if block.len() == 0 {
            break;
        }
        for i in 0..block.len() {
            tripple |= ( block[i] as u32 ) << ( 16 - (i * 8 ) )
        }

        // for each of the 6 bit blocks in tripple, convert to 8bits and
        // translate using table
        for i in 0..=3 {
            output.push( 
                table[ ((tripple >> (3 - i ) * 6) & 0x3F) as usize ]  
            );
        }
    }

    // pad if necessary
    for _i in 0..(input_length % 3) {
        output.push(b'=');
    }

    Ok(output)
}

pub fn base64decode( input: &[u8] ) -> Result< Vec<u8>, ConversionError> {
    let mut output = Vec::new();
    let table = HashMap::from( [
         (b'A',0), (b'B',1), (b'C',2), (b'D',3), (b'E',4),
         (b'F',5), (b'G',6), (b'H',7), (b'I',8), (b'J',9),
         (b'K',10), (b'L',11), (b'M',12), (b'N',13), (b'O',14),
         (b'P',15), (b'Q',16), (b'R',17), (b'S',18), (b'T',19),
         (b'U',20), (b'V',21), (b'W',22), (b'X',23), (b'Y',24),
         (b'Z',25), (b'a',26), (b'b',27), (b'c',28), (b'd',29),
         (b'e',30), (b'f',31), (b'g',32), (b'h',33), (b'i',34),
         (b'j',35), (b'k',36), (b'l',37), (b'm',38), (b'n',39),
         (b'o',40), (b'p',41), (b'q',42), (b'r',43), (b's',44),
         (b't',45), (b'u',46), (b'v',47), (b'w',48), (b'x',49),
         (b'y',50), (b'z',51), (b'0',52), (b'1',53), (b'2',54),
         (b'3',55), (b'4',56), (b'5',57), (b'6',58), (b'7',59),
         (b'8',60), (b'9',61), (b'+',62), (b'/',63),
    ]);
    // process 4 chars at a time
    for idx in 0..(input.len()/4 + 1 ){
        let end_idx = core::cmp::min( (idx * 4) + 4, input.len());
        let block = &input[ idx * 4 ..end_idx ];
        let mut quad = 0u32;
        if block.len() == 0 {
            break;
        }
        for i in 0..block.len(){
            let val = match table.get( &block[i] ) {
                Some(byte) => byte,
                None => return Err(ConversionError::InvalidIndex( block[i] ))
            };
            println!("{} {:08b}", i, val);
            quad |= ( *val as u32 ) << ( 26 - (i * 6 ));
            println!("quad: {:032b}", quad);
        }
        println!("done: {:032b}", quad);
        for i in 0..3 {
            let t = quad >> ( 24 - ( i * 8 )) & 0xFF;
            println!("t: {:08b}",t);
            output.push(  t as u8  );
        }
    }

    Ok(output)
}

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
    let encoded = base64encode( unhex.as_bytes()).unwrap();
    let pretty_encoded = String::from_utf8_lossy( encoded.as_slice() );
    println!("encoded: {:?}", pretty_encoded);
    assert_eq!( pretty_encoded , String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"));
}
