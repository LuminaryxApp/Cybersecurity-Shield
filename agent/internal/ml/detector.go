package ml

import (
	"math"
	"sync"
	"time"
)

type AnomalyType string

const (
	AnomalyZScore  AnomalyType = "zscore"
	AnomalyIQR     AnomalyType = "iqr"
	AnomalyRate    AnomalyType = "rate_change"
)

type Anomaly struct {
	Time       time.Time
	MetricName string
	Value      float64
	Score      float64
	Type       AnomalyType
	Threshold  float64
	Message    string
}

type MetricSeries struct {
	mu     sync.RWMutex
	name   string
	values []float64
	times  []time.Time
	maxLen int
}

func NewMetricSeries(name string, maxLen int) *MetricSeries {
	if maxLen <= 0 {
		maxLen = 1000
	}
	return &MetricSeries{
		name:   name,
		values: make([]float64, 0, maxLen),
		times:  make([]time.Time, 0, maxLen),
		maxLen: maxLen,
	}
}

func (s *MetricSeries) Add(t time.Time, value float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.values = append(s.values, value)
	s.times = append(s.times, t)

	if len(s.values) > s.maxLen {
		excess := len(s.values) - s.maxLen
		s.values = s.values[excess:]
		s.times = s.times[excess:]
	}
}

func (s *MetricSeries) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.values)
}

func (s *MetricSeries) Values() []float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]float64, len(s.values))
	copy(result, s.values)
	return result
}

func (s *MetricSeries) Last() (float64, time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.values) == 0 {
		return 0, time.Time{}, false
	}
	return s.values[len(s.values)-1], s.times[len(s.times)-1], true
}

type AnomalyDetector struct {
	mu         sync.RWMutex
	series     map[string]*MetricSeries
	zThreshold float64
	iqrFactor  float64
	minSamples int
	windowSize int
}

func NewAnomalyDetector(zThreshold, iqrFactor float64, minSamples, windowSize int) *AnomalyDetector {
	if zThreshold <= 0 {
		zThreshold = 3.0
	}
	if iqrFactor <= 0 {
		iqrFactor = 1.5
	}
	if minSamples <= 0 {
		minSamples = 30
	}
	if windowSize <= 0 {
		windowSize = 100
	}
	return &AnomalyDetector{
		series:     make(map[string]*MetricSeries),
		zThreshold: zThreshold,
		iqrFactor:  iqrFactor,
		minSamples: minSamples,
		windowSize: windowSize,
	}
}

func (d *AnomalyDetector) Record(metricName string, t time.Time, value float64) []Anomaly {
	d.mu.Lock()
	s, exists := d.series[metricName]
	if !exists {
		s = NewMetricSeries(metricName, d.windowSize*10)
		d.series[metricName] = s
	}
	d.mu.Unlock()

	s.Add(t, value)

	if s.Len() < d.minSamples {
		return nil
	}

	var anomalies []Anomaly

	if a := d.checkZScore(s, t, value); a != nil {
		anomalies = append(anomalies, *a)
	}

	if a := d.checkIQR(s, t, value); a != nil {
		anomalies = append(anomalies, *a)
	}

	if a := d.checkRateChange(s, t, value); a != nil {
		anomalies = append(anomalies, *a)
	}

	return anomalies
}

func (d *AnomalyDetector) checkZScore(s *MetricSeries, t time.Time, value float64) *Anomaly {
	values := s.Values()
	if len(values) < d.minSamples {
		return nil
	}

	window := values
	if len(window) > d.windowSize {
		window = window[len(window)-d.windowSize:]
	}

	mean := Mean(window[:len(window)-1])
	stddev := StdDev(window[:len(window)-1])

	if stddev == 0 {
		return nil
	}

	zscore := math.Abs((value - mean) / stddev)

	if zscore > d.zThreshold {
		return &Anomaly{
			Time:       t,
			MetricName: s.name,
			Value:      value,
			Score:      zscore,
			Type:       AnomalyZScore,
			Threshold:  d.zThreshold,
			Message:    "Value deviates significantly from the mean",
		}
	}

	return nil
}

func (d *AnomalyDetector) checkIQR(s *MetricSeries, t time.Time, value float64) *Anomaly {
	values := s.Values()
	if len(values) < d.minSamples {
		return nil
	}

	window := values
	if len(window) > d.windowSize {
		window = window[len(window)-d.windowSize:]
	}

	sorted := make([]float64, len(window)-1)
	copy(sorted, window[:len(window)-1])
	sortFloat64s(sorted)

	q1 := Percentile(sorted, 25)
	q3 := Percentile(sorted, 75)
	iqr := q3 - q1

	if iqr == 0 {
		return nil
	}

	lowerBound := q1 - d.iqrFactor*iqr
	upperBound := q3 + d.iqrFactor*iqr

	if value < lowerBound || value > upperBound {
		deviation := 0.0
		if value > upperBound {
			deviation = (value - upperBound) / iqr
		} else {
			deviation = (lowerBound - value) / iqr
		}

		return &Anomaly{
			Time:       t,
			MetricName: s.name,
			Value:      value,
			Score:      deviation,
			Type:       AnomalyIQR,
			Threshold:  d.iqrFactor,
			Message:    "Value is an outlier based on IQR analysis",
		}
	}

	return nil
}

func (d *AnomalyDetector) checkRateChange(s *MetricSeries, t time.Time, value float64) *Anomaly {
	values := s.Values()
	if len(values) < d.minSamples {
		return nil
	}

	window := values
	if len(window) > d.windowSize {
		window = window[len(window)-d.windowSize:]
	}

	recentAvg := Mean(window[len(window)-5:])
	historicalAvg := Mean(window[:len(window)-5])

	if historicalAvg == 0 {
		return nil
	}

	rateChange := math.Abs((recentAvg - historicalAvg) / historicalAvg)

	if rateChange > 0.5 {
		return &Anomaly{
			Time:       t,
			MetricName: s.name,
			Value:      value,
			Score:      rateChange,
			Type:       AnomalyRate,
			Threshold:  0.5,
			Message:    "Significant rate of change detected",
		}
	}

	return nil
}

func (d *AnomalyDetector) GetSeries(name string) *MetricSeries {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.series[name]
}

func (d *AnomalyDetector) SeriesCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.series)
}
