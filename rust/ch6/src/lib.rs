use ch2::{fixed_xor};
use ch3::{break_xor_byte};
use ch1::{pause};

#[derive(Debug,Clone,Eq,PartialEq)]
pub enum Ch6Error{
    InvalidRowLength
}

pub fn hamming_distance( x0 : &[u8], x1: &[u8]) -> Option<u64>{
    let mut distance = 0;
    let xor = match fixed_xor( x0, x1 ) {
        Ok(xor) => xor,
        Err(e) => { 
            println!("failed fixed_xor {:?}",e); 
            return None
        },
    };
    for byte in xor {
        for i in 0..8 {
            if byte & ( 1 << i ) > 0{
                distance +=1;
            }
        }
    }
    return Some(distance)
}

/* tried two blocks but that failed to find the key length */
pub fn xor_key_lengths( buf: &[u8] ) -> Option<Vec<usize>>{
    let mut kl_distance = Vec::new();
    for kl in 2..=40 {
        if buf.len() < kl * 4 {
            break;
        }
        let b0 = &buf[ (kl * 0) .. (kl * 1) ];
        let b1 = &buf[ (kl * 1) .. (kl * 2) ];
        let b2 = &buf[ (kl * 2) .. (kl * 3) ];
        let b3 = &buf[ (kl * 3) .. (kl * 4) ];
        let mut distance = 0u64;
        /* should write a combinations function */
        distance += (( hamming_distance( &b0, &b1 )? as f64 / kl as f64 )
                             * 1000.0f64 ) as u64;
        distance += (( hamming_distance( &b0, &b2 )? as f64 / kl as f64 )
                             * 1000.0f64 ) as u64;
        distance += (( hamming_distance( &b0, &b3 )? as f64 / kl as f64 )
                             * 1000.0f64 ) as u64;
        distance += (( hamming_distance( &b1, &b2 )? as f64 / kl as f64 )
                             * 1000.0f64 ) as u64;
        distance += (( hamming_distance( &b1, &b3 )? as f64 / kl as f64 )
                             * 1000.0f64 ) as u64;
        distance += (( hamming_distance( &b2, &b3 )? as f64 / kl as f64 )
                             * 1000.0f64 ) as u64;

        distance = ((distance as f64 / 4 as f64) * 100.0f64 )as u64;
        kl_distance.push( (distance, kl ) );
    }
    kl_distance.sort_by_key( |k| k.0);
    
    let possible_kl: Vec<usize> = kl_distance[0..=4]
                                    .into_iter().map(|x| x.1).collect();
    Some(possible_kl)
}

/*
transposes `v` as follows
v = [ [1,2,3,4,5], [1,2,3,4,5], [1,2,3,4,5]
T = [ [1,1,1], [2,2,2], [3,3,3], [4,4,4], [5,5,5] ]
expects all nested vectors to be the same size or returns nothing
*/

pub fn transpose<T>(v: Vec<Vec<T>>) -> 
        Result< Vec<Vec<T>>, Ch6Error>
where
    T: Copy
{
    let block_len = v[0].len();
    for block in &v {
        if block.len() != block_len {
            return Err(Ch6Error::InvalidRowLength)
        }
    }
    let mut stream: Vec<T> = Vec::with_capacity( block_len * v.len());
    for i in 0..block_len {
        for block in &v{
            stream.push( block[i] );
        }
    }
    let tblocks: Vec<Vec<T>> = stream.chunks_exact( v.len() )
                                        .map( |s| s.into()).collect();
    Ok(tblocks)
}

pub fn recover_xor_key( buf: &[u8], kl: usize ) -> Option<Vec<u8>> {
    let mut key = vec![0u8; kl ];
    let mut padded_buf = buf.to_vec();
    for _i in 0..(kl -( buf.len() % kl )){
        padded_buf.push( 0u8 );
    }
    let kl_blocks: Vec<Vec<u8>> = padded_buf.chunks(kl)
                                        .map(|s| s.into()).collect();

    let t_blocks = transpose(kl_blocks).expect("failed to transpose");
    for (idx, tblock) in t_blocks.iter().enumerate() {
        let (_score, k, _xord ) = break_xor_byte( tblock.as_slice() );
        key[idx] = k ;
    }
    Some(key)
}
