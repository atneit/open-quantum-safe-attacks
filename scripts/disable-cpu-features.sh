#!/bin/sh

echo "# querying scaling_driver"

cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_driver

echo
echo "# Abort if the output above is NOT intel_pstate for each logical CPU"
read -p "Press enter to continue (or Ctrl+C to abort)"

echo "Disabling turbo boost"
echo "1" | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

