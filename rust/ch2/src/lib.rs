#[derive(Debug)]
pub enum Ch2Error {
    InvalidLength
}

pub fn fixed_xor( x0: &[u8], x1: &[u8]) -> Result< Vec<u8>,Ch2Error > {
    if x0.len() != x1.len() {
        return Err(Ch2Error::InvalidLength)
    }
    let mut output = Vec::with_capacity( x0.len() );
    for i in 0..x0.len(){
        output.push( x0[i] ^ x1[i]);
    }
    Ok(output)
}
