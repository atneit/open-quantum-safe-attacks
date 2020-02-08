#![feature(test)]
use test::{black_box, Bencher};

macro_rules! memshift {
    () => {{
        let x = black_box(0);
        let x = black_box(x + 1);

        let x=black_box(x+1);
        

        black_box(x); // Silence 'unused variable' warning.
    }};
}
