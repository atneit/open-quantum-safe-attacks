### A Pluto.jl notebook ###
# v0.15.1

using Markdown
using InteractiveUtils

# ╔═╡ 05733db8-7b38-11eb-1eac-d38939448656
params_N = [
	23869
	45197
	69259
	
	20553
	38923
	59957
	
	17669
	35851
	57637
	]

# ╔═╡ 14d61c1c-7b38-11eb-2240-17194a64875b
params_N1 = [
	766
	766
	796
	
	80
	76
	78
	
	46
	56
	90
]

# ╔═╡ 1844fc56-7b38-11eb-02e2-a91bf9507e22
params_N2 = [
	31
	59
	87
	
	256
	512
	768
	
	384
	640
	640
]

# ╔═╡ 21d30326-7b38-11eb-0b4e-7be60d111545
params_N1N2 = params_N1 .* params_N2

# ╔═╡ 239d551c-7b38-11eb-1a2a-d17b57c08d32
params_K = [
	256
	256
	256
	
	32*8
	32*8
	32*8
	
	16*8
	24*8
	32*8
	]

# ╔═╡ a9580943-edd6-44b4-8e93-8b0fcf4b7e3c
params_W = [
	67
	101
	133
	
	67
	101
	133
	
	66
	100
	131
]

# ╔═╡ 24223ac0-7b38-11eb-190e-73c5627f4453
params_WE = [
	77
	117
	153
	
	77
	117
	153
	
	75
	114
	149
	]

# ╔═╡ d4446c34-8d94-11eb-25c2-2517bec6816e
params_SECURITY = [
	128
	192
	256
	128
	192
	256
	128
	192
	256
]

# ╔═╡ 27396e5e-7b38-11eb-336d-bddda1fce268
params_PBASE = BigInt.([ # Rejection sampling success probability
	16756038
	16768087
	16760678
		
	16775461
	16775813	
	16728003
	
	16767881
	16742417
	16772367
	]) .// 2^24

# ╔═╡ 2a27994a-7b38-11eb-353e-87dbb61eed2a
params = collect(zip(params_WE, params_N, params_PBASE))

# ╔═╡ 2fd03836-7b38-11eb-04cc-4d439609eb6e
params_NAMES = begin
	names_tmp = [ 
	"r6-bch-128" #ye
	"r6-bch-192" #ye
	"r6-bch-256"
	"r6-rmrs-128" #ye
	"r6-rmrs-192"
	"r6-rmrs-256"
	"r7-rmrs-128" #ye
	"r7-rmrs-192" #ye
	"r7-rmrs-256" #ye
]
	reshape(names_tmp, 1, length(names_tmp))
end

# ╔═╡ 3b002b6c-7b38-11eb-1a7a-69d87c2e568e
params

# ╔═╡ Cell order:
# ╠═05733db8-7b38-11eb-1eac-d38939448656
# ╠═14d61c1c-7b38-11eb-2240-17194a64875b
# ╠═1844fc56-7b38-11eb-02e2-a91bf9507e22
# ╠═21d30326-7b38-11eb-0b4e-7be60d111545
# ╠═239d551c-7b38-11eb-1a2a-d17b57c08d32
# ╠═a9580943-edd6-44b4-8e93-8b0fcf4b7e3c
# ╠═24223ac0-7b38-11eb-190e-73c5627f4453
# ╠═d4446c34-8d94-11eb-25c2-2517bec6816e
# ╠═27396e5e-7b38-11eb-336d-bddda1fce268
# ╠═2a27994a-7b38-11eb-353e-87dbb61eed2a
# ╠═2fd03836-7b38-11eb-04cc-4d439609eb6e
# ╠═3b002b6c-7b38-11eb-1a7a-69d87c2e568e
