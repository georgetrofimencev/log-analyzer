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


NGINX_PATTERN = re.compile(r'^\S+\s\S+\s{2}\S+\s\[.*?\]\s\"\S+\s(\S+)\s\S+\"\s\S+\s\S+\s.+?\s\".+?\"\s\S+\s\S+\s\S+\s(\S+)')


config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": ".reports/",
    "LOG_DIR": "../log_analyzer/log/",
    "LOGGING_FILE": "test.log",
}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_ERRORS_LIMIT = 0.2

logger = getLogger(__name__)

parser = argparse.ArgumentParser(description="Nginx logs analyzer")
parser.add_argument(
    "--config",
    dest="config_path",
    help="Path of config. If not specified " "script downloads default settings",
)


def start_logging(cfg):
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
     #   filename=cfg.get("LOGGING_FILE"),
    )


def load_config_from_path(config_path: str, default):
    default_config = copy.deepcopy(default)
    try:
        cfg = importlib.import_module(f"{config_path}").config
    except (AttributeError, ModuleNotFoundError) as ex:
        print('ERROR! File with settings not found!')
        return ex
    default_config.update(cfg)
    return default_config


def get_report_name(log_name):
    date = re.findall(r"\d+", log_name)[0]
    part_date = f"{date[:4]}.{date[4:6]}.{date[-2:]}"
    return "report-{}.html".format(part_date)


def report_already_exists(log_name, report_dir):
    try:
        ls = os.listdir(report_dir)
        report_name = get_report_name(log_name)
        reports = [report for report in ls if report == report_name]
        return False if len(reports) == 0 else True
    except FileNotFoundError:
        os.makedirs(report_dir)
        return False


def log_date(log_file):
    file_date = re.match(r'^.*-(\d+)\.?\w*$', log_file)
    if file_date:
        try:
            return datetime.strptime(file_date.group(1), '%Y%m%d')
        except ValueError:
            return None


def get_latest_logfile(log_dir):
    pattern = re.compile(r"(^nginx-access-ui.log-.*.gz$)|(^nginx-access-ui.log-\d+$)")
    log_files = [file for file in os.listdir(log_dir) if re.search(pattern, file)]
    return max([f for f in log_files if log_date(f)], key=log_date) if log_files else None


def parse_line(line):
    #  Надо ли парсить по регулярке всю лог-строку,
    #  если нужные данные находятся всегда в одном и том же положении?...
    res = NGINX_PATTERN.match(line)
    if res:
        parsed_line = (dict(zip(('request_url', 'request_time'), res.groups())))
        return parsed_line['request_url'], float(parsed_line['request_time'])
    return None, None


def _read(f_obj):
    for line in f_obj:
        yield line if line else None


def reading_file(log_path):
    with (gzip.open(log_path, 'rb') if log_path.endswith(".gz")
            else open(log_path, encoding="utf-8")) as file:
        yield from _read(file)


def analyze(log_dir, report_dir, report_size):
    logfile = get_latest_logfile(log_dir)
    if report_already_exists(logfile, report_dir):
        logger.info(f"Report of latest logfile already exists")
        return None
    logger.info("Starting to analyze nginx file with logs: {}...".format(logfile))
    logs_statistics = collections.defaultdict(list)
    total_count = total_time = errors_count = 0
    for line in reading_file(os.path.join(log_dir, logfile)):
        total_count += 1
        url, request_time = parse_line(line)
        if not url and not request_time:
            errors_count += 1
        else:
            total_time += request_time
            logs_statistics[url].append(request_time)

    if errors_count >= MAX_ERRORS_LIMIT * total_count:
        logger.error("Cannot read the file...")
        raise Exception

    logger.info("File is read.. Total Count Strings: {}".format(total_count))
    report_data = prepare_report_data(logs_statistics, total_count, total_time, report_size)
    return report_data


def render_html_report(data, report_dir, log_dir):
    logfile = get_latest_logfile(log_dir)
    report_name = get_report_name(logfile)
    with open("./templates/report.html", "r") as out:
        d_file = out.read()
    datafile = d_file.replace("$table_json", json.dumps(data))
    logger.info("Report rendering started...")
    with open(report_dir + report_name, "w") as in_:
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
    if isinstance(cfg, Exception):
        raise cfg
    start_logging(cfg)
    data = analyze(cfg["LOG_DIR"], cfg["REPORT_DIR"], cfg["REPORT_SIZE"])
    render_html_report(
        data, cfg["REPORT_DIR"], cfg["LOG_DIR"]
    ) if data else logger.info("Script completed")


if __name__ == "__main__":
    args = parser.parse_args()
    conf_path = args.config_path
    try:
        main(conf_path, config)
    except Exception as e:
        logger.exception(e)
        sys.exit(1)
