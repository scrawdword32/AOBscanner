# AOB Scanner (x64)

**AOB Scanner** is a lightweight C++ utility for scanning memory of Windows processes using byte patterns (Array of Bytes).  
It uses the Windows API and works at the system call level.

---

## 🚀 Features

- Scan memory for custom byte patterns  
- Support for masks (`x` = exact byte, `?` = wildcard)  
- Automatic module detection (EXE base address and size)  
- Uses `VirtualQueryEx` for accurate region scanning  
- Simple command-line interface with process name input  

---

## 🛠️ Build Instructions

### Requirements
- CMake 3.10 or higher  
- C++17 compatible compiler (MSVC / Clang / GCC)  
- Windows SDK  

### Steps
```bash
git clone https://github.com/scrawdword32/AOBscanner.git
cd AOBscanner
mkdir build && cd build
cmake ..
cmake --build .
