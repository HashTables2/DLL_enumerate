import pefile
import sys
import os

def enumerate_exports(dll_path):
    if not os.path.exists(dll_path):
        print(f"'{dll_path}' does not exist", file=sys.stderr)
        return None

    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    pe = pefile.PE(dll_path, fast_load=True)
    pe.parse_data_directories(directories=d)
    
    exports = []
    
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        try:
            export_name = e.name.decode()
            exports.append(export_name)
        except Exception as err:
            None
    
    return exports

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s <file_with_dll_paths>" % sys.argv[0], file=sys.stderr)
        sys.exit(1)

    filename = sys.argv[1]
    if not os.path.exists(filename):
        print(f"'{filename}' does not exist", file=sys.stderr)
        sys.exit(1)

    dll_exports = {}

    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()  # Remove trailing newlines
            if line:
                exports = enumerate_exports(line)
                if exports:
                    dll_name = os.path.basename(line)
                    dll_exports[dll_name] = exports

    print(dll_exports)
