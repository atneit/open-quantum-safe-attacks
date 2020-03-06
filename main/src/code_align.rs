macro_rules! memshift {
    () => {{
        use std::hint::black_box;
        let x = black_box(0);
        let x = black_box(x + 1);

        let x = black_box(x + 1);

        black_box(x); // Silence 'unused variable' warning.
    }};
}
