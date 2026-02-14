package ml

import (
	"math"
	"sort"
)

func Mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func Variance(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	mean := Mean(values)
	sumSq := 0.0
	for _, v := range values {
		diff := v - mean
		sumSq += diff * diff
	}
	return sumSq / float64(len(values)-1)
}

func StdDev(values []float64) float64 {
	return math.Sqrt(Variance(values))
}

func Percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}

	index := (p / 100.0) * float64(len(sorted)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))

	if lower == upper {
		return sorted[lower]
	}

	fraction := index - float64(lower)
	return sorted[lower]*(1-fraction) + sorted[upper]*fraction
}

func Median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	return Percentile(sorted, 50)
}

func MovingAverage(values []float64, window int) []float64 {
	if len(values) == 0 || window <= 0 {
		return nil
	}
	if window > len(values) {
		window = len(values)
	}

	result := make([]float64, 0, len(values)-window+1)
	sum := 0.0

	for i := 0; i < window; i++ {
		sum += values[i]
	}
	result = append(result, sum/float64(window))

	for i := window; i < len(values); i++ {
		sum += values[i] - values[i-window]
		result = append(result, sum/float64(window))
	}

	return result
}

func ExponentialMovingAverage(values []float64, alpha float64) []float64 {
	if len(values) == 0 {
		return nil
	}
	if alpha <= 0 || alpha > 1 {
		alpha = 0.1
	}

	result := make([]float64, len(values))
	result[0] = values[0]

	for i := 1; i < len(values); i++ {
		result[i] = alpha*values[i] + (1-alpha)*result[i-1]
	}

	return result
}

func ZScore(value, mean, stddev float64) float64 {
	if stddev == 0 {
		return 0
	}
	return (value - mean) / stddev
}

func MinMax(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	min := values[0]
	max := values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, max
}

func Normalize(values []float64) []float64 {
	if len(values) == 0 {
		return nil
	}
	min, max := MinMax(values)
	span := max - min
	if span == 0 {
		result := make([]float64, len(values))
		return result
	}

	result := make([]float64, len(values))
	for i, v := range values {
		result[i] = (v - min) / span
	}
	return result
}

func sortFloat64s(data []float64) {
	sort.Float64s(data)
}
