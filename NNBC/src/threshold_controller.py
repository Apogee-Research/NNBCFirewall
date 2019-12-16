
import time
import logging


class ThresholdController:
    def __init__(self, config, logname):
        self.config = config
        self.threshold = config['initial_threshold']
        self.health = config['setpoint']
        self.health_err = 0.0
        self.actuator_err = 0.0
        self.controller = PIController(
            config["K"], config["tau_i"], config["tau_t"], self.threshold)
        self.log = logging.getLogger(logname)
        self.log.info("Instantiated Threshold Controller with: %s", config)

    def update_threshold(self, under_attack, lb, ub):
        self.update_health(under_attack)
        unconstrained_threshold = self.controller.update(
           self.health_err, self.actuator_err)
        constrained_threshold = max(min(unconstrained_threshold, ub), lb)
        self.actuator_err = constrained_threshold - unconstrained_threshold
        self.log.debug("health %.2f | health_err %.2f | uthresh %.2f | "
                       "cthresh %.2f | lb %.2f | ub %.2f | act_error %.2f",
                       self.health, self.health_err, unconstrained_threshold,
                       constrained_threshold, lb, ub, self.actuator_err)
        return constrained_threshold

    def update_health(self, under_attack):
        a = self.config['sensor_smoothing_alpha']
        sensor = 0.0 if under_attack else 1.0
        self.health = (a * sensor) + ((1-a) * self.health)
        self.health_err = self.config["setpoint"] - self.health


class PIController:
    def __init__(self, k, tau_i, tau_t, s_init):
        self.K = k
        self.tau_i = tau_i
        self.tau_t = tau_t
        self.s = s_init
        self.last_ts = time.time()

    def update(self, e1, e2):
        now = time.time()
        dt = now - self.last_ts
        self.last_ts = now

        c = self.s + self.K * e1
        self.s = (self.s +
                  dt * self.K * e1 / self.tau_i +
                  dt * self.tau_t * self.tau_i * e2 / self.K)
        return c
