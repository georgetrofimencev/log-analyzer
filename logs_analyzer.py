import sys
import os
import argparse
import re
import gzip
import copy
import json
import collections
import importlib
import logging
from datetime import datetime
from statistics import median

from logging import getLogger


NGINX_PATTERN = re.compile(
    "(?P<remote_addr>.*?) "
    "(?P<remote_user>.*?) "
    "(?P<real_ip>.*?) \[(?P<date>.*?)(?= ) (?P<timezone>.*?)\] "
    '"(?P<request_method>.*?) (?P<url>.*?)(?P<request_version> HTTP/.*)?" '
    "(?P<status>.*?) "
    "(?P<length>.*?) "
    '"(?P<referrer>.*?)" '
    '"(?P<user_agent>.*?)" '
    '"(?P<forwarded_for>.*?)" '
    '"(?P<request_id>.*?)" '
    '"(?P<rb_user>.*?)" '
    "(?P<request_time>.*?)$"
)

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": ".reports/tests/test/",
    "LOG_DIR": "../log_analyzer/log/",
   # "LOGGING_FILE": "test.log",
}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_ERRORS_LIMIT = 0.2

parser = argparse.ArgumentParser(description="Nginx logs analyzer")
parser.add_argument(
    "--config",
    dest="config_path",
    help="Path of config. If not specified " "script downloads default settings",
)
logger = getLogger(__name__)

LogInfo = collections.namedtuple('LogInfo', ['path', 'date'])


def start_logging(cfg):
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        filename=cfg.get("LOGGING_FILE"),
    )


def load_config_from_path(config_path: str, default):
    default_config = copy.deepcopy(default)
    try:
        cfg = importlib.import_module(f"{config_path}").config
    except (AttributeError, ModuleNotFoundError):
        print("ERROR! File with settings not found!")
        raise FileNotFoundError
    default_config.update(cfg)
    return default_config


def get_report_name(date):
    part_date = date.strftime('%Y-%m-%d')
    return f"report-{part_date}.html"


def get_report_path(log, report_dir):
    report_name = get_report_name(log.date)
    path = os.path.join(report_dir, report_name)
    return path


def report_already_exists(path):
    if not os.path.exists(path):
        try:
            os.makedirs(os.path.split(path)[0])
        except FileExistsError:
            pass
        return False
    return True


def log_date(log_file):
    file_date = re.match(r"^.*-(\d+)\.?\w*$", log_file)
    if file_date:
        try:
            return datetime.strptime(file_date.group(1), "%Y%m%d")
        except ValueError:
            return None


def get_latest_logfile(log_dir):
    pattern = re.compile(r"(^nginx-access-ui.log-.*.gz$)|(^nginx-access-ui.log-\d+$)")
    log_files = [file for file in os.listdir(log_dir) if re.search(pattern, file)]
    latest = None
    for log in log_files:
        date = log_date(log)
        if not latest:
            latest = LogInfo(os.path.join(log_dir, log), date)
        if latest and date:
            if latest.date < date:
                latest = LogInfo(os.path.join(log_dir, log), date)
    return latest


def parse_line(line):
    match = re.match(NGINX_PATTERN, line)
    return match.groupdict() if match else None


def reading_file(log_path):
    with (
        gzip.open(log_path, "rb")
        if log_path.endswith(".gz")
        else open(log_path, encoding="utf-8")
    ) as file:
        for line in file:
            yield line if line else None


def analyze(report_size, logfile):
    logger.info("Starting to analyze nginx file with logs: {}...".format(logfile.path))
    logs_statistics = collections.defaultdict(list)
    total_count = total_time = errors_count = 0
    for line in reading_file(logfile.path):
        total_count += 1
        res = parse_line(line)
        if not res:
            errors_count += 1
        else:
            request_time = float(res["request_time"])
            url = res["url"]
            total_time += request_time
            logs_statistics[url].append(request_time)

    if errors_count >= MAX_ERRORS_LIMIT * total_count:
        logger.error("Cannot read the file...")
        raise Exception

    logger.info("File is read.. Total Count Strings: {}".format(total_count))
    report_data = prepare_report_data(
        logs_statistics, total_count, total_time, report_size
    )
    return report_data


def render_html_report(report_path, data):
    with open("./templates/report.html", "r") as out:
        d_file = out.read()
    datafile = d_file.replace("$table_json", json.dumps(data))
    logger.info("Report rendering started...")
    with open(report_path, "w") as in_:
        in_.write(datafile)
    logger.info("Report rendering completed...")


def prepare_report_data(logs_statistics, total_count, total_time, report_size):
    report_data = []
    one_c_percent = float(total_count / 100)
    one_t_percent = float(total_time / 100)
    for url, times in logs_statistics.items():
        count = len(times)
        time_sum = sum(times)
        data = {
            "url": str(url),
            "count": count,
            "count_perc": round(count / one_c_percent, 3),
            "time_sum": round(time_sum, 3),
            "time_max": max(times),
            "time_perc": round(time_sum / one_t_percent, 3),
            "time_avg": round(time_sum / count, 3),
            "time_med": round(median(times), 3),
        }
        report_data.append(data)
    logger.info("Data preparation completed!")
    report_data.sort(key=lambda x: (x["time_perc"]), reverse=True)
    return report_data[:report_size]


def main(cfg_path, default):
    cfg = default if not cfg_path else load_config_from_path(cfg_path, default)
    start_logging(cfg)
    logfile = get_latest_logfile(cfg["LOG_DIR"])
    report_path = get_report_path(logfile, cfg["REPORT_DIR"])
    if report_already_exists(report_path):
        logger.info(f"Report of latest logfile already exists")
        return None
    data = analyze(cfg["REPORT_SIZE"], logfile)
    render_html_report(report_path, data) if data else logger.info("No Data for Reporting...")
    logger.info("Script completed.")


if __name__ == "__main__":
    args = parser.parse_args()
    conf_path = args.config_path
    try:
        main(conf_path, config)
    except BaseException as exc:
        logger.exception(exc)
        sys.exit(1)
