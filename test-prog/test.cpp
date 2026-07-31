#include <print>
#include <stdint.h>
#include <vector>
#include <cmath>
#define NOINLINE __declspec(noinline)

NOINLINE double doMath() {
    volatile double result = 0.0;
    for (int i = 1; i < 1'000'000; ++i) {
        result += std::sin(i) * std::cos(i) + std::sqrt(i);
    }
    return result;
}

NOINLINE void func1() {
    auto result = doMath();

    size_t bufSize = 1'000'000;
    std::vector<uint64_t> data(bufSize);

    for (size_t i = 0; i < bufSize; ++i) {
        data[i] = (i * 131) ^ (result > 0 ? 0x55555555 : 0);
    }

    volatile uint64_t sum = 0;
    for (size_t i = 0; i < bufSize; i += 64) {
        sum += data[i];
    }
}

NOINLINE void func2() {
    func1();
    func1();
    func1();
}

NOINLINE void func3() {
    func2();
    func1();
}

NOINLINE void func4() {
    func1();
    func3();
}

NOINLINE void func5() {
    func3();
    func2();
    func1();
}

NOINLINE void func6() {
    func2();
    func5();
    func3();
}

NOINLINE void func7() {
    func6();
    func4();
    func2();
}

NOINLINE void func8() {
    func1();
    func6();
    func7();
}

NOINLINE void func9() {
    func1();
    func8();
    func4();
    func1();
}

NOINLINE void func10() {
    func2();
    func5();
    func9();
}

NOINLINE void recurse(int x = 10) {
    if (x == 0) func10();
    else {
        recurse(x - 1);
        func1();
    }
}

int main() {
    recurse();
}