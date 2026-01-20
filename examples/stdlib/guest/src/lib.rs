use jolt::jolt_println;

// #[jolt::provable(max_trace_length = 65536, stack_size = 1048576)]
// fn int_to_string(n: i32) -> i32 {
//     jolt_println!("Hello, from int_to_string! n = {}", n);
//     n
// }

// #[jolt::provable(max_trace_length = 65536, stack_size = 1048576)]
// fn string_concat(n: i32) -> String {
//     jolt_println!("Hello, world!");
//     let mut res = String::new();
//     for i in 0..n {
//         res += &i.to_string();
//     }

//     res
// }

/// Parallel sum of squares using rayon - same as ZeroOS std-smoke
/// Computes: 1² + 2² + 3² + ... + n²
/// For n=101, expected result = 348551
#[jolt::provable(max_trace_length = 65536, stack_size = 1048576)]
fn parallel_sum_of_squares(n: u32) -> u64 {
    jolt_println!("Computing parallel sum of squares from 1 to {}", n);

    // TODO: Re-enable rayon/threading once TLS + clone/thread setup is fully wired in the Jolt
    // execution environment. For now, keep the stdlib example runnable end-to-end.
    let mut result: u64 = 0;
    for x in 1..=n {
        result = result.wrapping_add((x as u64).wrapping_mul(x as u64));
    }

    jolt_println!("Result: {}", result);
    result
}

