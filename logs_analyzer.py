import sys
import os
import argparse
import re
import gzip
import json
import collections
import importlib
import logging

from statistics import median

from logging import getLogger

# NGINX_LOG_RE = re.\
# compile(r'(\d+.\d+.\d+.\d+) (\w+|-)\s\s(\w+|-) \[(.+)\] \"(.+) (.+) (.+) (\d+) (\d+) \"(.*)\" \"(.*)\" (\d.\d+)')

logger = getLogger(__name__)

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports/",
    "LOG_DIR": "./log/",
    "LOGGING_FILE": "test.log",
}

parser = argparse.ArgumentParser(description="Nginx logs analyzer")
parser.add_argument(
    "--config",
    dest="config_path",
    help="Path of config. If not specified " "script downloads default settings",
)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def start_logging(cfg):
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        filename=cfg.get("LOGGING_FILE"),
    )


def load_config_from_path(config_path: str, default):
    default_config = default
    try:
        cfg = importlib.import_module(f"{config_path}").config
        for param in cfg:
            default_config[param] = cfg[param]
    except ModuleNotFoundError:
        return None
    return default_config


def logger_decorator(func):
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            logger.exception(e)
            sys.exit(1)
        except KeyboardInterrupt as ctrl_c:
            logger.exception(ctrl_c)
            sys.exit(1)

    return wrapper


def get_report_name(log_name):
    date = re.findall(r"\d+", log_name)[0]
    part_date = f"{date[:4]}.{date[4:6]}.{date[-2:]}"
    return "report-{}.html".format(part_date)


def report_already_exists(log_name, report_dir):
    ls = os.listdir(report_dir)
    report_name = get_report_name(log_name)
    actual_date = re.compile("^{}$".format(report_name))
    reports = [report for report in ls if re.search(actual_date, report)]

    return False if len(reports) == 0 else True


def get_latest_logfile(log_dir):
    pattern = re.compile(r"(^nginx-access-ui.log-.*.gz$)|(^nginx-access-ui.log-\d+$)")
    log_files = [file for file in os.listdir(log_dir) if re.search(pattern, file)]

    last_logfile = max(log_files, key=lambda file: re.findall(r"\d+", file)[0])
    return last_logfile


def parse_line(line):
    #  Надо ли парсить по регулярке всю лог-строку,
    #  если нужные данные находятся всегда в одном и том же положении?...
    res = line.split()
    return res[6], float(res[-1])  # url, request_time


def reading_file(log_path):
    if log_path.endswith(".gz"):
        file = gzip.open(log_path, "rb")
    else:
        file = open(log_path, encoding="utf-8")
    for line in file:
        if line:
            yield line
    file.close()


def analyze(log_dir, report_dir, report_size):
    logfile = get_latest_logfile(log_dir)
    if report_already_exists(logfile, report_dir):
        logger.info(f"Report of latest logfile already exists")
        return None
    logger.info("Starting to analyze nginx file with logs: {}...".format(logfile))
    logs_statistics = collections.defaultdict(list)
    total_count = total_time = 0
    for line in reading_file(log_dir + logfile):
        url, request_time = parse_line(line)
        total_count += 1
        total_time += request_time
        logs_statistics[url].append(request_time)
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
    completed = 0
    try:
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
            completed += 1
            if completed % 10000 == 0:
                total_result = round(completed * 100 / len(logs_statistics.items()), 3)
                logger.debug("Process: {}%".format(total_result))
        logger.info("Data preparation completed!")
        report_data.sort(key=lambda x: (x["time_perc"]), reverse=True)
        return report_data[:report_size]
    except Exception as e:
        logger.error(e)
        total_result = round(completed * 100 / len(logs_statistics.items()), 3)
        logger.error("Process failed! Analyzed {}%".format(total_result))
        raise e


@logger_decorator
def main(cfg_path, default):
    cfg = default if not cfg_path else load_config_from_path(cfg_path, default)
    start_logging(cfg)
    data = analyze(cfg["LOG_DIR"], cfg["REPORT_DIR"], cfg["REPORT_SIZE"])
    render_html_report(
        data, cfg["REPORT_DIR"], cfg["LOG_DIR"]
    ) if data else logger.info("Script completed")


if __name__ == "__main__":
    args = parser.parse_args()
    main(vars(args).get("config"), config)
