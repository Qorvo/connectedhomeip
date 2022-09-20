#!/usr/bin/env python3
"""
Clean all non-needed submodules for Qorvo builds
"""
import os
import configparser

CHIP_ROOT = os.path.dirname(__file__)

min_qpg_sdk_submodule_list = [
    "third_party/mbedtls/repo"
]
min_matter_build_submodule_list = [
    "third_party/nlassert/repo",
    "third_party/nlio/repo",
    "third_party/nlunit-test/repo",
    "third_party/editline/repo",
    "third_party/freertos/repo",
    "third_party/openthread/repo",
    "third_party/openthread/ot-qorvo",
    "third_party/pigweed/repo",
    "third_party/qpg_sdk/repo",
    "third_party/zap/repo",
    "third_party/jsoncpp/repo",
    "third_party/nlfaultinjection/repo"
]

def load_module_info() -> list:
    config = configparser.ConfigParser()
    config.read(os.path.join(CHIP_ROOT, '.gitmodules'))

    paths = []
    for name, module in config.items():
        if name != 'DEFAULT':
            # print (name)
            # print (module["path"])
            paths.append(module["path"])

    return paths

def remove_submodule(path : str):
    os.system(f"git rm -f {path}")

def main():
    submodules = load_module_info()

    modules_to_remove = set(submodules) - set(min_qpg_sdk_submodule_list) - set(min_matter_build_submodule_list)
    print (f"Removing: {modules_to_remove}")
    for submodule_path in modules_to_remove:
        remove_submodule(submodule_path)

if __name__ == '__main__':
    main()
