#!/usr/bin/env python

import time
import logging
import os
import shutil
import numpy as np
from threading import Thread
from collections import deque
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

html_template = '''
<html>
<head>
<meta http-equiv="refresh" content="10">
<style>
  img {{
    max-height: 100%;
    max-width: 100%;
    margin: auto;
  }}
</style>
</head>
<body>
<img src="nnbc_summary.png">
<h2>Sensor Success Over Last 5 Minutes: {} / {} = {:.2f}%</h2>
<h2>Tracking {} Client IP Addresses</h2>
</body>
</html>
'''


class Moment:
    ''' A container for all the data we collect about a
        particular moment in the life of the NNBC '''
    def __init__(self, ts, t1_threshold, t2_threshold, t1_health, t2_health, scores, under_attack):
        self.timestamp = ts
        self.thresholds = dict(t1=t1_threshold, t2=t2_threshold)
        self.healths = dict(t1=t1_health, t2=t2_health)
        self.scores = dict(t1=None, t2=None)
        t1_scores = [t[1] for t in scores]
        t2_scores = [t[2] for t in scores]
        if t1_scores:
            self.scores["t1"] = (
                min(t1_scores), np.percentile(t1_scores, 25), np.median(t1_scores),
                np.percentile(t1_scores, 75), max(t1_scores))
        if t2_scores:
            self.scores["t2"] = (
                min(t2_scores), np.percentile(t2_scores, 25), np.median(t2_scores),
                np.percentile(t2_scores, 75), max(t2_scores))
        self.under_attack = under_attack


class StatisticsGatherer(Thread):
    def __init__(self, max_windows, logname):
        self.windows = deque([], max_windows)
        self.log = logging.getLogger(logname)
        logging.getLogger("matplotlib").setLevel(logging.WARNING)
        shutil.rmtree("/tmp/nnbc_stats/", ignore_errors=True)
        os.mkdir("/tmp/nnbc_stats/")
        self.num_scores = 0
        super().__init__()
        self.daemon = True
        self.start()

    def add_data(self, ts, t1_thresh, t2_thresh, t1_health, t2_health, scores, under_attack):
        m = Moment(ts, t1_thresh, t2_thresh, t1_health, t2_health, scores, under_attack)
        self.windows.append(m)
        self.num_scores = len(scores)

    def run(self):
        while True:
            try:
                self.create_html_report()
            except:
                self.log.exception("Unexpected error in StatisticsGatherer")
            time.sleep(10)

    def create_html_report(self):
        moments = list(self.windows)
        self.create_image(moments)
        success, total, perc = self.sensor_stats(moments)
        with open("/tmp/nnbc_stats/index.html", 'w') as f:
            f.write(html_template.format(success, total, perc, self.num_scores))

    def create_image(self, moments):
        gs = matplotlib.gridspec.GridSpec(3, 1, height_ratios=[1, 3, 3])
        fig = plt.figure(figsize=(16, 8))
        sensor_ax = plt.subplot(gs[0])
        t1_ax = plt.subplot(gs[1], sharex=sensor_ax)
        t2_ax = plt.subplot(gs[2], sharex=sensor_ax)
        self.plot_sensor(sensor_ax, moments)
        self.plot_thresh_scores(t1_ax, moments, "t1")
        self.plot_thresh_scores(t2_ax, moments, "t2")
        t1_ax.set_title("T1 Scores and Threshold")
        t2_ax.set_title("T2 Scores and Threshold")
        t2_ax.set_xlabel("Seconds since NNBC initialization")
        fig.tight_layout()
        fig.savefig("/tmp/nnbc_stats/nnbc_summary.png")
        plt.close(fig)

    @staticmethod
    def plot_sensor(ax, moments):
        xa = []
        xn = []
        for m in moments:
            if m.under_attack:
                xa.append(m.timestamp)
            else:
                xn.append(m.timestamp)
        ax.scatter(xn, [0]*len(xn), label="No Attack", color="green")
        ax.scatter(xa, [0]*len(xa), label="Attack", color="red")
        ax.set_title("Sensor Measurements")
        ax.set_yticks([], [])
        ax.grid()
        ax.legend(loc="upper left")

    @staticmethod
    def plot_thresh_scores(ax, moments, key):
        xt = []
        yt = []
        xc = []
        yc = []

        for m in moments:
            xt.append(m.timestamp)
            yt.append(m.thresholds[key])
            if m.scores[key] is not None:
                xc.append(m.timestamp)
                yc.append(m.scores[key])
        ax.plot(xt, yt, color="black", label="threshold")
        if yc:
            ymin, y25, ymed, y75, ymax = zip(*yc)
            ax.fill_between(xc, ymin, ymax, color="blue", alpha=0.2, label="min/max scores")
            ax.fill_between(xc, y25, y75, color="blue", alpha=0.4, label="25th/75th percentile scores")
            ax.plot(xc, ymed, color="blue", label="median score")
        ax.set_ylim(top=0)
        ax.grid()
        ax.legend(loc="upper left")

    @staticmethod
    def sensor_stats(moments):
        successes = len([m for m in moments if not m.under_attack])
        total = len(moments)
        if total == 0:
            return 0, 0, 100.0
        else:
            return successes, total, float(successes)/total*100.0
