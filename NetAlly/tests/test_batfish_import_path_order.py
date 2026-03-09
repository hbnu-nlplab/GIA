import sys

from agent.clients import batfish as batfish_module


def test_make_dataset_path_is_not_prepended_to_sys_path():
    target = str(batfish_module.MAKE_DATASET_PATH)
    if target in sys.path:
        assert sys.path.index(target) > 0
