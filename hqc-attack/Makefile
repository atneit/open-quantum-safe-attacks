.PHONY: clean build-attack attack attackstats collect-timings figures

clean:
	rm -rf results

build-attack:
	docker build -f Dockerfile.attack -t hqc-attack .

attack: build-attack
	docker run -it --rm hqc-attack

attackstats: build-attack
	mkdir -p results/attackstats results/attackstats/last_lines
	docker build -f Dockerfile.attackstats -t hqc-attackstats .
	docker run -it --rm -v "$(realpath results/attackstats):/collect_attack_stats/results" --entrypoint=../run.sh hqc-attackstats 1000

collect-timings: build-attack 
	mkdir -p results/timings
	docker build -f Dockerfile.timings -t hqc-attack-timings .
	docker run -it --rm -v "$(realpath results/timings):/hqc/nist-release-2021-06-06/Optimized_Implementation/hqc-128/results/timings" hqc-attack-timings

figures: # collect-timings
	mkdir -p results
	cp --reflink=auto "$$(ls -t results/attackstats/results_*.csv | head -n1)" results/attackstats/results.csv
	docker build -f Dockerfile.figures -t hqc-attack-figures .
	docker run -it --rm -v "$(realpath results):/results" hqc-attack-figures
