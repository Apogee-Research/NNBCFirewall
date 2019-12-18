#!/usr/bin/env python3

import time
import threading
import subprocess as sp
import psycopg2
import logging
import logging.handlers
import yaml
import os
import sys
import redis
import signal
from threshold_controller import ThresholdController
from statistics import StatisticsGatherer


UPDATE_ENTRIES_UNDER_ATTACK = '''
UPDATE nnbc_clients SET
t1_score = t1_score - (%s * (accesses + connections) + %s * misbehaviors),
t2_score = t2_score - (t2_access_multiplier * (accesses + connections + misbehaviors)),
accesses = 0, misbehaviors = 0;
UPDATE nnbc_clients SET
t1_score = ( case when t2_score > %s then t1_score * %s else t1_score end ),
t2_score = t2_score * %s,
t2_access_multiplier = ( case when t2_score > %s and t2_blocked then
                         2 * t2_access_multiplier else t2_access_multiplier end ),
t2_blocked = t2_blocked and t2_score < %s
RETURNING addr, t1_score, t2_score'''


UPDATE_ENTRIES_NO_ATTACK = '''
UPDATE nnbc_clients SET
t1_score = ( case when t2_score > %s then t1_score * %s else t1_score end ),
t2_score = t2_score * %s;
UPDATE nnbc_clients SET
t1_score = t1_score - (%s * misbehaviors),
t2_score = t2_score - (t2_access_multiplier * misbehaviors),
accesses = 0, misbehaviors = 0,
t2_access_multiplier = ( case when t2_blocked and t2_score >= %s then
                         2 * t2_access_multiplier else t2_access_multiplier end ),
t2_blocked = t2_blocked and t2_score < %s
RETURNING addr, t1_score, t2_score'''


class NNBC(threading.Thread):

    def __init__(self, config_path):
        self.config = self.parse_config(config_path)
        self.log = self.setup_logger()
        self.start_time = time.time()
        self.stop_flag = False
        self.log.info("T0: %d", int(self.start_time))
        self.tc1 = ThresholdController(self.config["t1_threshold_controller"],
                                       "nnbc.t1_controller")
        self.tc2 = ThresholdController(self.config["t2_threshold_controller"],
                                       "nnbc.t2_controller")
        self.t1_threshold = self.tc1.threshold
        self.t2_threshold = self.tc2.threshold
        self.stats = StatisticsGatherer(150, "nnbc.stats")
        self.clients_present_flag = False
        self.myredis = redis.Redis()
        super().__init__()

    @staticmethod
    def parse_config(config_path):
        if not os.path.isfile(config_path):
            print("config file <%s> not found" % config_path)
            sys.exit(1)
        with open(config_path) as f:
            return yaml.load(f)

    def setup_logger(self):
        log = logging.getLogger("nnbc")
        f = logging.Formatter("%(created).2f : %(levelname)s : %(name)s : %(message)s")
        lev = logging.DEBUG if self.config.get("debug", True) else logging.WARNING
        log.setLevel(lev)
        if "logfile" not in self.config:
            h = logging.StreamHandler()
        else:
            h = logging.handlers.WatchedFileHandler(self.config["logfile"], mode='w')
        h.setLevel(lev)
        h.setFormatter(f)
        log.addHandler(h)
        return log

    def stop(self):
        self.stop_flag = True

    def restart_proxy(self):
        self.log.warning("Restarting the NNBC firewall.")
        sp.call(['/usr/local/nginx-nnbc/sbin/nginx', '-s', 'stop'])

    def run(self):
        ''' MAIN LOOP '''
        sensor_iter = int(self.start_time)
        # Keep track of how many consecutive sensor failures we have,
        # so that we can restart the firewall if needed.
        consecutive_failures = 0
        ninety_percent_health = 0
        one_thousand_failures = 0
        while not self.stop_flag:
            iter_start = time.time()
            seconds = int(iter_start - self.start_time)
            under_attack = self.do_sensor(sensor_iter)
            if under_attack and not self.clients_present_flag:
                self.log.warning("Sensor failed, but masking under_attack signal "
                                 "because there have been no clients yet.")
                under_attack = False
            sensor_iter += 1

            if under_attack:
                consecutive_failures = consecutive_failures + 1
                one_thousand_failures = one_thousand_failures + 1
                ninety_percent_health = ninety_percent_health + 1.0
            else:
                consecutive_failures = 0
                if ninety_percent_health > 0.1:
                    ninety_percent_health = ninety_percent_health - 0.1
            self.log.info("GLF: consecutive_failures = %d, ninety_percent_health = %f", consecutive_failures, ninety_percent_health)
            restart_now = False
            if consecutive_failures > 10:
                restart_now = True
            if ninety_percent_health > 20:
                restart_now = True
            if one_thousand_failures >= 1000:
                restart_now = True

            if restart_now:
                consecutive_failures = 0
                one_thousand_failures = 0
                ninety_percent_health = 0
                self.restart_proxy()

            client_scores = self.do_update_queries(under_attack)
            if not self.clients_present_flag and len(client_scores) > 0:
                self.log.info("Clients have appeared")
                self.clients_present_flag = True
            t1_min, t2_min = self.calculate_threshold_constraints(client_scores)
            self.t1_threshold = self.tc1.update_threshold(under_attack, t1_min, -0.1)
            self.t2_threshold = self.tc2.update_threshold(under_attack, t2_min, -0.1)
            self.publish_redis(under_attack)
            self.dump_to_log(seconds, client_scores, under_attack)
            self.stats.add_data(seconds, self.t1_threshold, self.t2_threshold,
                                self.tc1.health, self.tc2.health,
                                client_scores, under_attack)
            iter_stop = time.time()
            time_left = self.config["sensor_poll"] - (iter_stop - iter_start)
            if time_left > 0:
                time.sleep(time_left)
            else:
                self.log.warning("Iteration took %.2f seconds!",
                                 self.config["sensor_poll"] - time_left)

    def do_sensor(self, sensor_iter):
        cmd = self.config["sensor_cmd"]
        cmd_timeout = self.config["sensor_poll"] - 0.5
        if "%ld" in cmd:
            cmd = cmd % sensor_iter
        try:
            ret = sp.call(cmd.split(), timeout=cmd_timeout)
        except sp.TimeoutExpired:
            self.log.warning("Sensor cmd <%s> timed out after %.1f seconds",
                             cmd, cmd_timeout)
            ret = None
        self.log.debug("Sensor cmd <%s> returned %s", cmd, ret)
        return False if ret == 0 else True

    def do_update_queries(self, under_attack):
        dbconf = self.config["database"]
        with psycopg2.connect(**dbconf) as conn:
            with conn.cursor() as cur:
                if under_attack:
                    cur.execute(
                        UPDATE_ENTRIES_UNDER_ATTACK, (
                            self.config["t1_access_multiplier"],
                            self.config["t1_misbehave_multiplier"],
                            self.t2_threshold,
                            self.config["t1_reduction_factor"],
                            self.config["t2_reduction_factor"],
                            self.t2_threshold,
                            self.t2_threshold))
                    return cur.fetchall()
                else:
                    cur.execute(
                        UPDATE_ENTRIES_NO_ATTACK, (
                            self.t2_threshold,
                            self.config["t1_reduction_factor"],
                            self.config["t2_reduction_factor"],
                            self.config["t1_misbehave_multiplier"],
                            self.t2_threshold,
                            self.t2_threshold))
                    return cur.fetchall()

    def calculate_threshold_constraints(self, client_scores):
        t1_smin = 0.0
        t2_smin = 0.0
        filtered_t1_scores = [t1_score for addr, t1_score, t2_score in client_scores
                              if t2_score > self.t2_threshold]
        if filtered_t1_scores:
            t1_smin = min(filtered_t1_scores)
        t2_scores = [t2_score for addr, t1_score, t2_score in client_scores]
        if t2_scores:
            t2_smin = min(t2_scores)
        t1_min = t1_smin - self.config["t1_max_distance_below"]
        t2_min = t2_smin - self.config["t2_max_distance_below"]
        return t1_min, t2_min

    def publish_redis(self, under_attack):
        # publish under_attack
        val = 1 if under_attack else 0
        self.log.info("GLF: Published under_attack: %s", val)
        self.myredis.publish(self.config["under_attack_channel"], val)

        # publish thresholds
        self.myredis.publish(self.config["t1_threshold_channel"], self.t1_threshold)
        self.myredis.publish(self.config["t2_threshold_channel"], self.t2_threshold)

    def dump_to_log(self, seconds, client_scores, under_attack):
        with open(self.config["dump_log"], 'a') as f:
            f.write("START_ITERATION\nseconds: %d\nunder_attack: %s\n"
                    "t1_threshold: %.2f\nt2_threshold: %.2f\n" % (
                        seconds, "1" if under_attack else "0",
                        self.t1_threshold, self.t2_threshold))
            for addr, t1, t2 in client_scores:
                f.write("%s: %.2f %.2f\n" % (addr, t1, t2))
            f.write("END_ITERATION\n")


if __name__ == "__main__":
    cfg_path = os.path.abspath(sys.argv[1])
    nnbc = NNBC(cfg_path)
    signal.signal(signal.SIGINT, lambda sig, frame: nnbc.stop())
    nnbc.start()
    nnbc.join()
