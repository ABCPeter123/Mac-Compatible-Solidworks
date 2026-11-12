// Original Windows C++17 executable built with MSVC /MD, not MinGW.
// Exercises dynamic VC++ STL and C Runtime calls. Does not use SOLIDWORKS.
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <iterator>
#include <system_error>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

int main() {
    namespace fs = std::filesystem;
    fs::path path;
    try {
        std::vector<int> numbers = {9, 3, 7, 1, 5, 11};
        std::sort(numbers.begin(), numbers.end());
        if (numbers != std::vector<int>({1, 3, 5, 7, 9, 11}))
            throw std::runtime_error("STL sort incorrect");

        int sum = std::accumulate(numbers.begin(), numbers.end(), 0);
        if (sum != 36) throw std::runtime_error("STL numeric incorrect");
        std::puts("SWCOMPAT_MSVC_STL=PASS");

        std::future<int> future = std::async(std::launch::async, [sum] {
            std::vector<int> data(1000, 1);
            return std::accumulate(data.begin(), data.end(), sum);
        });
        if (future.get() != 1036) throw std::runtime_error("async result mismatch");
        std::puts("SWCOMPAT_MSVC_ASYNC=PASS");

        std::ostringstream out;
        out << "sum=" << sum << ";items=" << numbers.size();
        if (out.str() != "sum=36;items=6")
            throw std::runtime_error("stream formatting mismatch");
        std::puts("SWCOMPAT_MSVC_STREAM=PASS");

        path = fs::temp_directory_path() / "swcompat-msvc-runtime-test.tmp";
        {
            std::ofstream stream(path, std::ios::binary | std::ios::trunc);
            if (!stream) throw std::runtime_error("cannot open temp file");
            stream << out.str();
        }
        std::ifstream input(path, std::ios::binary);
        if (!input) throw std::runtime_error("cannot read temp file");
        std::string content((std::istreambuf_iterator<char>(input)),
                            std::istreambuf_iterator<char>());
        if (content != out.str()) throw std::runtime_error("file read mismatch");
        std::puts("SWCOMPAT_MSVC_FILEIO=PASS");
        input.close();
        fs::remove(path);
        path.clear();

        static_assert(sizeof(void*) == 4 || sizeof(void*) == 8, "Windows pointer size");
        std::printf("SWCOMPAT_MSVC_PROCESS_BITS=%u\n", unsigned(sizeof(void*) * 8));
        std::puts("SWCOMPAT_MSVC_RUNTIME=PASS");
        std::fflush(stdout);
        return 0;
    } catch (const std::exception &ex) {
        std::printf("SWCOMPAT_MSVC_ERROR=%s\n", ex.what());
        std::puts("SWCOMPAT_MSVC_RUNTIME=FAIL");
        if (!path.empty()) {
            std::error_code ignored;
            fs::remove(path, ignored);
        }
        return 1;
    }
}
