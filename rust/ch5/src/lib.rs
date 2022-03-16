
pub fn repeat_xor( buf: &mut [u8], key: &[u8]){
    let mut k = 0;
    for i in 0..buf.len(){
        buf[i] ^= key[k];
        k= (k + 1) % key.len();
    }
}
