import os.path

WRITE_FSTAT_TIMES = True

_configs = {
	"__pkg_name":"com.xx.oo",
	"pkg_name":"com.xx.qq.11",
	"pid": 4386,
	"uid": 10023,
	"android_id": "39cc04a2ae83db0b",
	"ip":"192.168.31.52",
	"mac":[204, 250, 166, 0, 138, 169]
}

import json
def global_config_init(cfg_path):
    if not os.path.isfile(cfg_path):
        return

    global _configs
    with open(cfg_path, "r") as f:
        js = f.read()
        _configs = json.loads(js)


def global_config_get(key):
    global _configs
    if key in _configs.keys():
        return _configs[key]
    else:
        return key+"missing"

