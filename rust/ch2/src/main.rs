use ch1::{hex2bin,b64encode, b64decode };

fn main() {
    let foo = b64encode(String::from("ABCD").as_bytes() );
    println!("Hello, world! {:?}", foo);
}
