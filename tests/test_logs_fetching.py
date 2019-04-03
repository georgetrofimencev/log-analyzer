import unittest
from logs_analyzer import \
    BASE_DIR, \
    get_latest_logfile, \
    report_already_exists, \
    get_report_name


test_logs_dir = BASE_DIR + '/tests/testdata/logs'
test_reports_dir = BASE_DIR + '/tests/testdata/reports'


class TestLogsNginxFetcherCase(unittest.TestCase):
    def test_last_logfile(self):
        logfile = get_latest_logfile(test_logs_dir)
        self.assertEqual(logfile, 'nginx-access-ui.log-20180730.gz')

    def test_last_logfile_if_logdir_not_exists(self):
        with self.assertRaises(FileNotFoundError):
            logfile = get_latest_logfile(test_logs_dir + 'failed')

    def test_check_report_file_if_file_exists(self):
        logfile = get_latest_logfile(test_logs_dir)
        check = report_already_exists(logfile, test_reports_dir)
        self.assertTrue(check)

    def test_check_report_file_if_file_not_exists(self):
        logfile = get_latest_logfile(test_logs_dir)
        check = report_already_exists(logfile, BASE_DIR + '/tests/testdata')
        self.assertFalse(check)

    def test_get_report_name(self):
        logfile = get_latest_logfile(test_logs_dir)
        report_name = get_report_name(logfile)
        self.assertEqual(report_name, 'report-2018.07.30.html')


if __name__ == '__main__':
    unittest.main()
