class ConfidenceCalibrator:
    @staticmethod
    def calibrate(raw_score: float, false_positive_rate: float = 0.05, true_positive_rate: float = 0.90) -> float:
        """Calibrates raw scores based on agent error profiles:
        P(T | Alert) = P(Alert | T) * P(T) / P(Alert)
        """
        prior = 0.10  # assume 10% base threat rate
        p_alert_given_t = true_positive_rate
        p_alert_given_not_t = false_positive_rate
        
        p_alert = (p_alert_given_t * prior) + (p_alert_given_not_t * (1.0 - prior))
        posterior = (p_alert_given_t * prior) / p_alert if p_alert > 0 else prior
        
        # Scale score according to posterior
        calibrated = (raw_score * 0.3) + (posterior * 0.7)
        return round(max(0.01, min(0.99, calibrated)), 3)
