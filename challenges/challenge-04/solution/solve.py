def naive_step(n):
    return (n * 11 + 1362691243) & 0xffffffff


def combine_linear_functions(f, g):
    """
    Suppose you want to combine two linear functions f and g
    f := x -> ax+b
    g := x -> cx+d

    What you want is h := f . g
    h x = a(cx + d) + b = acx + ad + b

    So h := x -> (ac)x + (ad + b)
    """

    a, b = f
    c, d = g

    return (a*c) & 0xffffffff, (a*d + b) & 0xffffffff

def apply_linear_function(f, n):
    a, b = f
    return (a*n + b) & 0xffffffff

def exponential(steps, n):
    # x -> 11x + 1362691243
    params = (11, 1362691243)

    # x -> x
    out = (1, 0)

    while steps:
        if steps & 1:
            out = combine_linear_functions(params, out)
        params = combine_linear_functions(params, params)
        steps >>= 1
    return apply_linear_function(out, n)

initial = 0o02643075365
cur = initial

for i in range(100_000):
    e = exponential(i, initial)
    assert cur == e
    cur = naive_step(cur)

assert exponential(0, initial) == initial
assert exponential(2**31, initial) == initial
assert exponential(2**30, initial) != initial
assert exponential(5, initial) == 0o10674715172
print("potluck{" + oct(exponential(0o707000000005, initial))[2:] + "}")
