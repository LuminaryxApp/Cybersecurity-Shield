package ml_test

import (
	"math"
	"testing"

	"github.com/LuminaryxApp/Cybersecurity-Shield/agent/internal/ml"
)

func almostEqual(a, b, epsilon float64) bool {
	return math.Abs(a-b) < epsilon
}

func TestMean(t *testing.T) {
	tests := []struct {
		values   []float64
		expected float64
	}{
		{[]float64{1, 2, 3, 4, 5}, 3.0},
		{[]float64{10}, 10.0},
		{[]float64{}, 0.0},
		{[]float64{-1, 1}, 0.0},
	}

	for _, tt := range tests {
		result := ml.Mean(tt.values)
		if !almostEqual(result, tt.expected, 0.001) {
			t.Errorf("Mean(%v) = %f, want %f", tt.values, result, tt.expected)
		}
	}
}

func TestVariance(t *testing.T) {
	values := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	v := ml.Variance(values)
	if !almostEqual(v, 4.571, 0.01) {
		t.Errorf("Variance = %f, want ~4.571", v)
	}

	if ml.Variance([]float64{}) != 0 {
		t.Error("expected 0 for empty slice")
	}
	if ml.Variance([]float64{5}) != 0 {
		t.Error("expected 0 for single element")
	}
}

func TestStdDev(t *testing.T) {
	values := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	sd := ml.StdDev(values)
	if !almostEqual(sd, 2.138, 0.01) {
		t.Errorf("StdDev = %f, want ~2.138", sd)
	}
}

func TestPercentile(t *testing.T) {
	sorted := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	p25 := ml.Percentile(sorted, 25)
	if !almostEqual(p25, 3.25, 0.01) {
		t.Errorf("P25 = %f, want ~3.25", p25)
	}

	p50 := ml.Percentile(sorted, 50)
	if !almostEqual(p50, 5.5, 0.01) {
		t.Errorf("P50 = %f, want ~5.5", p50)
	}

	p75 := ml.Percentile(sorted, 75)
	if !almostEqual(p75, 7.75, 0.01) {
		t.Errorf("P75 = %f, want ~7.75", p75)
	}

	if ml.Percentile([]float64{}, 50) != 0 {
		t.Error("expected 0 for empty slice")
	}
}

func TestMedian(t *testing.T) {
	if !almostEqual(ml.Median([]float64{1, 3, 5}), 3.0, 0.001) {
		t.Error("odd median failed")
	}
	if !almostEqual(ml.Median([]float64{1, 2, 3, 4}), 2.5, 0.001) {
		t.Error("even median failed")
	}
	if ml.Median([]float64{}) != 0 {
		t.Error("empty median should be 0")
	}
}

func TestMovingAverage(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	ma := ml.MovingAverage(values, 3)

	if len(ma) != 8 {
		t.Fatalf("expected 8 elements, got %d", len(ma))
	}
	if !almostEqual(ma[0], 2.0, 0.001) {
		t.Errorf("ma[0] = %f, want 2.0", ma[0])
	}
	if !almostEqual(ma[7], 9.0, 0.001) {
		t.Errorf("ma[7] = %f, want 9.0", ma[7])
	}

	if ml.MovingAverage(nil, 3) != nil {
		t.Error("nil input should return nil")
	}
}

func TestExponentialMovingAverage(t *testing.T) {
	values := []float64{10, 12, 11, 13, 14, 12, 15}
	ema := ml.ExponentialMovingAverage(values, 0.3)

	if len(ema) != len(values) {
		t.Fatalf("expected %d elements, got %d", len(values), len(ema))
	}
	if ema[0] != 10.0 {
		t.Errorf("ema[0] = %f, want 10.0", ema[0])
	}
	if ema[1] <= ema[0] {
		t.Error("ema should increase after higher value")
	}
}

func TestZScore(t *testing.T) {
	z := ml.ZScore(15, 10, 2)
	if !almostEqual(z, 2.5, 0.001) {
		t.Errorf("ZScore = %f, want 2.5", z)
	}

	if ml.ZScore(10, 10, 0) != 0 {
		t.Error("ZScore with 0 stddev should be 0")
	}
}

func TestMinMax(t *testing.T) {
	min, max := ml.MinMax([]float64{5, 3, 8, 1, 9, 2})
	if min != 1 || max != 9 {
		t.Errorf("MinMax = (%f, %f), want (1, 9)", min, max)
	}

	min, max = ml.MinMax([]float64{})
	if min != 0 || max != 0 {
		t.Error("empty MinMax should be (0, 0)")
	}
}

func TestNormalize(t *testing.T) {
	values := []float64{2, 4, 6, 8, 10}
	norm := ml.Normalize(values)

	if !almostEqual(norm[0], 0.0, 0.001) {
		t.Errorf("norm[0] = %f, want 0.0", norm[0])
	}
	if !almostEqual(norm[4], 1.0, 0.001) {
		t.Errorf("norm[4] = %f, want 1.0", norm[4])
	}
	if !almostEqual(norm[2], 0.5, 0.001) {
		t.Errorf("norm[2] = %f, want 0.5", norm[2])
	}

	constant := ml.Normalize([]float64{5, 5, 5})
	for _, v := range constant {
		if v != 0 {
			t.Errorf("normalize constant should be all 0, got %f", v)
		}
	}
}
