### A Pluto.jl notebook ###
# v0.14.0

using Markdown
using InteractiveUtils

# ╔═╡ 9ead6e06-8d88-11eb-217f-8b56c2aecb22
using DataFrames, CSV, Latexify, Statistics, DataFramesMeta, StatsBase

# ╔═╡ 66b598ba-8d89-11eb-3396-e354a6160e5b
using Plots

# ╔═╡ b4b08ed6-8d88-11eb-24e5-9fb2257cce24
function load_benchmark(p)
	df = CSV.File("../timings/$(p)") |> DataFrame
	dfstd = std(df.time)
	dfmean = mean(df.time)
	@where(df, :time .< dfmean + dfstd * 3)
	#df
end

# ╔═╡ eae16d0c-8d88-11eb-1c2d-f90d59ec0c72
benchmarks = [
	("original", "timings_messages_original.csv"),
	("seedexpander fix", "timings_messages_countermeasure_1.csv"),
	("RNG fix", "timings_messages_countermeasure_2.csv"),
	("final", "timings_messages_countermeasure_3.csv"),
]

# ╔═╡ d968a560-8d88-11eb-1873-998f7c1b9392
ds = map(x -> load_benchmark(x[2]), benchmarks)

# ╔═╡ e4f4f982-8d89-11eb-32f9-41c081fcf7dc
sort(collect(Set(ds[3].inner)))

# ╔═╡ 117b8c9c-8d89-11eb-3be4-c142e8a46d08
labels = map(first, benchmarks)

# ╔═╡ 1c2e6c04-8d89-11eb-3abe-21272ecd187c
dmean = convert.(Int, round.(map(x -> mean(x.time), ds)))

# ╔═╡ 441aa6d8-8d89-11eb-1772-030a7cb193ed
dmedian = map(x -> median(x.time), ds)

# ╔═╡ 48d70fa6-8d89-11eb-3831-b92b539742bd
dsd = map(x -> std(x.time), ds)

# ╔═╡ 92dd5244-8e2f-11eb-0e20-77ec7dbc83be
cov = map(x -> variation(x.time), ds)

# ╔═╡ 26bc5bca-8e30-11eb-3539-f548e41a8836
covc = (1 .- cov[2:end] ./ cov[1]).*100

# ╔═╡ cc58606a-8e30-11eb-1d91-bda2d29540a5
medianc = (dmedian[2:end] ./ dmedian[1] .- 1) .* 100

# ╔═╡ efcef9b0-937f-11eb-03d0-5b2f5ee3b9e0
df = DataFrame(name=labels, mean=dmean, median=convert.(Int, round.(dmedian)), medianc=[0; round.(medianc, digits=1)])#, dsd=round.(dsd), cov=round.(cov, digits=5), covc=[0; round.(covc,digits=2)])

# ╔═╡ 54e71328-9380-11eb-3c03-433503b7a3da
println(latexify(df, env=:table, latex=false))

# ╔═╡ 6ace29ee-8d89-11eb-171f-c5f10422e6ff
histogram(ds[4].time)

# ╔═╡ 4506a28e-9380-11eb-01bd-3351e60b0c1d


# ╔═╡ Cell order:
# ╠═9ead6e06-8d88-11eb-217f-8b56c2aecb22
# ╠═b4b08ed6-8d88-11eb-24e5-9fb2257cce24
# ╠═eae16d0c-8d88-11eb-1c2d-f90d59ec0c72
# ╠═d968a560-8d88-11eb-1873-998f7c1b9392
# ╠═e4f4f982-8d89-11eb-32f9-41c081fcf7dc
# ╠═117b8c9c-8d89-11eb-3be4-c142e8a46d08
# ╠═1c2e6c04-8d89-11eb-3abe-21272ecd187c
# ╠═441aa6d8-8d89-11eb-1772-030a7cb193ed
# ╠═48d70fa6-8d89-11eb-3831-b92b539742bd
# ╠═92dd5244-8e2f-11eb-0e20-77ec7dbc83be
# ╠═26bc5bca-8e30-11eb-3539-f548e41a8836
# ╠═cc58606a-8e30-11eb-1d91-bda2d29540a5
# ╠═efcef9b0-937f-11eb-03d0-5b2f5ee3b9e0
# ╠═54e71328-9380-11eb-3c03-433503b7a3da
# ╠═66b598ba-8d89-11eb-3396-e354a6160e5b
# ╠═6ace29ee-8d89-11eb-171f-c5f10422e6ff
# ╠═4506a28e-9380-11eb-01bd-3351e60b0c1d
