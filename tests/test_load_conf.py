import unittest
from logs_analyzer import load_config_from_path, config
from tests.testdata.confs.test_conf import config as test_conf
from tests.testdata.confs.test_merge_conf import config as test_merge


class LoadConfigTestCase(unittest.TestCase):
    """
        Test loading config. Merge configs and invalid config_path
    """

    def test_load_config_with_argument(self):
        conf = load_config_from_path("tests.testdata.confs.test_conf", config)
        self.assertEqual(conf.get("REPORT_SIZE"), test_conf.get("REPORT_SIZE"))
        self.assertEqual(conf.get("REPORT_DIR"), test_conf.get("REPORT_DIR"))
        self.assertEqual(conf.get("LOG_DIR"), test_conf.get("LOG_DIR"))

    def test_load_merge_config(self):
        conf = load_config_from_path("tests.testdata.confs.test_merge_conf", config)
        self.assertEqual(conf.get("REPORT_SIZE"), test_merge.get("REPORT_SIZE"))
        self.assertEqual(conf.get("REPORT_DIR"), test_merge.get("REPORT_DIR"))
        self.assertEqual(conf.get("LOG_DIR"), config.get("LOG_DIR"))

    def test_fail_config_path(self):
        conf = load_config_from_path("fail_path", config)
        self.assertIsNone(conf)


if __name__ == "__main__":
    unittest.main()
