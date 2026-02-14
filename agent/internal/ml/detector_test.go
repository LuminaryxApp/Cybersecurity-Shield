package ml_test

import (
	"testing"
	"time"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/ml"
)

func TestMetricSeries(t *testing.T) {
	s := ml.NewMetricSeries("test_metric", 5)

	if s.Len() != 0 {
		t.Errorf("expected 0 length, got %d", s.Len())
	}

	now := time.Now()
	s.Add(now, 1.0)
	s.Add(now.Add(time.Second), 2.0)
	s.Add(now.Add(2*time.Second), 3.0)

	if s.Len() != 3 {
		t.Errorf("expected 3 length, got %d", s.Len())
	}

	val, ts, ok := s.Last()
	if !ok {
		t.Error("expected Last to return true")
	}
	if val != 3.0 {
		t.Errorf("expected last value 3.0, got %f", val)
	}
	if ts.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestMetricSeriesMaxLen(t *testing.T) {
	s := ml.NewMetricSeries("bounded", 3)

	now := time.Now()
	for i := 0; i < 10; i++ {
		s.Add(now.Add(time.Duration(i)*time.Second), float64(i))
	}

	if s.Len() != 3 {
		t.Errorf("expected 3 after overflow, got %d", s.Len())
	}

	values := s.Values()
	if values[0] != 7.0 {
		t.Errorf("expected oldest value 7.0, got %f", values[0])
	}
}

func TestMetricSeriesEmptyLast(t *testing.T) {
	s := ml.NewMetricSeries("empty", 10)
	_, _, ok := s.Last()
	if ok {
		t.Error("expected Last to return false on empty series")
	}
}

func TestAnomalyDetectorCreation(t *testing.T) {
	d := ml.NewAnomalyDetector(0, 0, 0, 0)
	if d == nil {
		t.Fatal("expected non-nil detector")
	}
	if d.SeriesCount() != 0 {
		t.Errorf("expected 0 series, got %d", d.SeriesCount())
	}
}

func TestAnomalyDetectorNoAnomalyWithFewSamples(t *testing.T) {
	d := ml.NewAnomalyDetector(3.0, 1.5, 30, 100)

	now := time.Now()
	for i := 0; i < 10; i++ {
		anomalies := d.Record("cpu", now.Add(time.Duration(i)*time.Second), float64(50+i))
		if len(anomalies) > 0 {
			t.Errorf("expected no anomalies with %d samples, got %d", i+1, len(anomalies))
		}
	}
}

func TestAnomalyDetectorZScore(t *testing.T) {
	d := ml.NewAnomalyDetector(2.5, 10.0, 20, 100)

	now := time.Now()
	// Use slightly varying data to ensure non-zero stddev
	for i := 0; i < 50; i++ {
		value := 50.0 + float64(i%3) // values: 50, 51, 52, 50, 51, 52, ...
		d.Record("cpu", now.Add(time.Duration(i)*time.Second), value)
	}

	anomalies := d.Record("cpu", now.Add(51*time.Second), 200.0)

	foundZScore := false
	for _, a := range anomalies {
		if a.Type == ml.AnomalyZScore {
			foundZScore = true
			if a.MetricName != "cpu" {
				t.Errorf("expected metric 'cpu', got %s", a.MetricName)
			}
			if a.Value != 200.0 {
				t.Errorf("expected value 200.0, got %f", a.Value)
			}
		}
	}

	if !foundZScore {
		t.Error("expected z-score anomaly for extreme value 200.0 after 50 samples of 50.0")
	}
}

func TestAnomalyDetectorIQR(t *testing.T) {
	d := ml.NewAnomalyDetector(10.0, 1.5, 20, 100)

	now := time.Now()
	for i := 0; i < 50; i++ {
		value := 50.0 + float64(i%5)
		d.Record("memory", now.Add(time.Duration(i)*time.Second), value)
	}

	anomalies := d.Record("memory", now.Add(51*time.Second), 500.0)

	foundIQR := false
	for _, a := range anomalies {
		if a.Type == ml.AnomalyIQR {
			foundIQR = true
		}
	}

	if !foundIQR {
		t.Error("expected IQR anomaly for extreme value 500.0")
	}
}

func TestAnomalyDetectorRateChange(t *testing.T) {
	d := ml.NewAnomalyDetector(10.0, 10.0, 20, 100)

	now := time.Now()
	for i := 0; i < 45; i++ {
		d.Record("requests", now.Add(time.Duration(i)*time.Second), 100.0)
	}

	for i := 45; i < 50; i++ {
		anomalies := d.Record("requests", now.Add(time.Duration(i)*time.Second), 200.0)
		_ = anomalies
	}

	anomalies := d.Record("requests", now.Add(51*time.Second), 200.0)

	foundRate := false
	for _, a := range anomalies {
		if a.Type == ml.AnomalyRate {
			foundRate = true
		}
	}

	if !foundRate {
		t.Error("expected rate change anomaly when values doubled")
	}
}

func TestAnomalyDetectorNoAnomalyForNormalData(t *testing.T) {
	d := ml.NewAnomalyDetector(3.0, 1.5, 20, 100)

	now := time.Now()
	for i := 0; i < 100; i++ {
		value := 50.0 + float64(i%3)
		anomalies := d.Record("normal_metric", now.Add(time.Duration(i)*time.Second), value)
		for _, a := range anomalies {
			if a.Type == ml.AnomalyZScore || a.Type == ml.AnomalyIQR {
				t.Errorf("unexpected anomaly on normal data at sample %d: type=%s score=%f value=%f",
					i, a.Type, a.Score, a.Value)
			}
		}
	}
}

func TestAnomalyDetectorMultipleSeries(t *testing.T) {
	d := ml.NewAnomalyDetector(3.0, 1.5, 20, 100)

	now := time.Now()
	for i := 0; i < 30; i++ {
		d.Record("cpu", now.Add(time.Duration(i)*time.Second), 50.0)
		d.Record("memory", now.Add(time.Duration(i)*time.Second), 75.0)
	}

	if d.SeriesCount() != 2 {
		t.Errorf("expected 2 series, got %d", d.SeriesCount())
	}

	cpuSeries := d.GetSeries("cpu")
	if cpuSeries == nil {
		t.Fatal("expected cpu series to exist")
	}
	if cpuSeries.Len() != 30 {
		t.Errorf("expected 30 cpu samples, got %d", cpuSeries.Len())
	}
}
