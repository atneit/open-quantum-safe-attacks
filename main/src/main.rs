use liboqs_rs_bindings;

fn main() {
    let a = unsafe { liboqs_rs_bindings::OQS_KEM_alg_count() };
    println!("alg count: {}!", a);
}
