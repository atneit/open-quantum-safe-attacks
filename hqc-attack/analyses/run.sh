#!/usr/bin/env bash

mkdir -p ../results/figures
cd ../results/figures
julia --project=../../analyses ../../analyses/timing_messages.jl&
julia --project=../../analyses ../../analyses/benchmark_statistics.jl&
julia --project=../../analyses ../../analyses/analyze_timings.jl&
julia --project=../../analyses ../../analyses/empirical_success_prob.jl&
julia --project=../../analyses ../../analyses/rejection_sampling_probabilities.jl&
wait