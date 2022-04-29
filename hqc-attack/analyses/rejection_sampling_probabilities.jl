### A Pluto.jl notebook ###
# v0.17.2

using Markdown
using InteractiveUtils

# ╔═╡ c999c71e-2081-11eb-08d0-394b8bacd1cb
using Memoize

# ╔═╡ e862dac6-44a5-11eb-0cd0-a717546aa912
using OffsetArrays

# ╔═╡ 58cbf960-2088-11eb-3576-b77801d0ecae
using Plots, PGFPlotsX

# ╔═╡ 68aef322-8d9e-11eb-3a36-ab8de8bf8d4f
using Latexify

# ╔═╡ 6750687c-20e2-11eb-174d-7b428cdfee0d
using DataFrames

# ╔═╡ a8259e8a-20e2-11eb-2257-edcf371886d4
using StatsPlots

# ╔═╡ cab79ff0-5fe1-11eb-35bd-a1126ad2e3d0
using StatsBase, LinearAlgebra

# ╔═╡ f06458ee-7b37-11eb-1678-2b7ff63fd134
include("utils.jl")

# ╔═╡ 015f8f92-7b38-11eb-0782-4f56419b6d75
include("params.jl")

# ╔═╡ 7c7f5616-2085-11eb-0c34-19e84a55912c
@memoize function p(its, len, m, p_base)
	# Return probability of having len bits sampled successfuly
	# without rejections after its iterations
	# In other words: probability of sampling len distinct values
	# from {1, ..., m} after its iterations
	if its < len
		return 0
	end
	if its == 1 && len == 1
		return p_base
	end
	if its == 0 && len == 0
		return 1
	end
	s = 0
	if its > 0
		p_collision = len//m
		p_success = p_base * (1 - p_collision)
		# There is some chance of rejection
		s += (1 - p_success) * p(its-1, len, m, p_base)
	end
	if len > 0
		p_collision = max(0, (len-1)//m)
		p_success = p_base * (1 - p_collision)
		# There is some chance of success
		s += p_success * p(its-1, len-1, m, p_base)
	end
	return s
end

# ╔═╡ b07cb028-44a5-11eb-2515-ff56762cb362
function p_x(n, max_its, p_s)
  ps = OffsetArray(zeros(max_its+1, max_its+1), 0:max_its, 0:max_its)
  ps[0,0] = 1
  for i=0:max_its-1
    for w=0:i
      p_collision = min(w, n)/n
      success_and_not_collide = p_s * (1 - p_collision)
      ps[w+1, i+1] += ps[w, i] * success_and_not_collide
      ps[w  , i+1] += ps[w, i] * (1-success_and_not_collide)
    end
  end
  ps
end

# ╔═╡ b240cd22-44a5-11eb-1d9b-43a2f61426f8
begin
	ps = p_x(4, 6, .75)
	ps, sum(ps, dims=1), sum(ps[3:end, :], dims=1)
end

# ╔═╡ d6230b46-3fbf-11eb-0eeb-1fc88a3f750f
[p(its, len, 4, .75) for len=0:6, its=0:6]

# ╔═╡ b54bc926-3ff6-11eb-1ca8-6330113eab6d
sn(n, k) = 1//factorial(k) * reduce(+, collect((-1)^i * binomial(k, i) * (k-i)^n for i in 0:k), init=0) # stirling number of the 2nd kind

# ╔═╡ baed15a6-3ff6-11eb-3169-494beb92dc53
pc(n, w, i) = if i < w
	0
else
	reduce(*, collect((n-x)//n for x in 1:w-1), init=1) * sn(i, w)//n^(i-w)
end

# ╔═╡ fa86d996-404f-11eb-16fc-d1294cbc2ad8
[convert(Float64, pc(big"4", BigInt(len), BigInt(its))) for len=0:10, its=0:10]

# ╔═╡ 2246bdb4-208b-11eb-15e8-350713fd42e9
@memoize function P(its, len, m, p_base)
	# Returns the probability of taking ≤ its iterations
	# to obtain a vector with exactly len bits set
	if len > its
		return 0
	end
	p(its, len, m, p_base) + P(its, len+1, m, p_base)
end

# ╔═╡ 1d6febb8-2279-11eb-0411-e916df2e0da4
pgfplotsx()

# ╔═╡ 2c71c9b8-208a-11eb-2334-794198d4fb63
data = BigFloat.([ P(its, len, 6, 1.) for its=0:9, len=0:9 ])

# ╔═╡ 26d59634-2086-11eb-13b0-7dad3b1751fd
heatmap(0:9, 0:9, data, xlab="Length", ylab="Iters", xticks=0:9, yticks=0:9)

# ╔═╡ 5d151c74-20d1-11eb-2610-03d7bb5a5744
setprecision(2000)

# ╔═╡ 9e401752-20d2-11eb-0336-f104e0d96d05
function f(n, w, k, p_base)
	# w: weight
	# k: bit positions
	# p_base: success probability of internal rejection sampling
	# Return probability of exactly n seed expansions for a single vector sampling
	if n == 0
		p(w, w, k, p_base)
	else
		# P(X = 1) = P(Y ≤ 77*2-1) - P(Y ≤ 77)
		P(w*(n+1)-1, w, k, p_base) - P(w*n, w, k, p_base)
	end
end

# ╔═╡ 46072f6c-24f8-11eb-3571-151e9ebeea63
@assert all([ f(0, params[j]...) - prod(params_PBASE[j] * BigFloat(params_N[j]-i)/params_N[j] for i in 0:params_WE[j]-1) for j in 1:length(params)] .< 1e100)

# ╔═╡ aaba6da0-405f-11eb-116c-933bd36e48b1
BigFloat(sum(p(i, params_WE[2], params_N[2], params_PBASE[2]) for i in 75:75))

# ╔═╡ d60c1128-2504-11eb-1da7-fd7d0be5b076
prod(params_PBASE[2] * BigFloat(params_N[2]-i)/params_N[2] for i in 0:params_WE[2]-1)

# ╔═╡ db492024-24fd-11eb-0d28-53126b605321
[BigFloat(f(0, param...))*100 for param in params]

# ╔═╡ 46f82718-20dd-11eb-317b-9710e5bb8aa0
@memoize function p_dice(dice, sides, n, p)
	# Returns the probability dice number of dice with side ∈ sides
	# sum up to n
	if dice == 1
		pr = p(n) # probability of this outcome
		if n < 0
			@assert pr == 0 # should be the case for the probability distributions we have
		end
		return pr
	end
	if n ∉ sides
		return BigInt(0)
	end
	return sum(p(outcome) * p_dice(dice-1, sides, n-outcome, p) for outcome in sides)
end

# ╔═╡ 9f1b9ebd-daf0-4dbf-80d9-6bf6969afdbb
# Probability of number of inner iterations
#BigFloat(sum([ p_dice(3, 0:2*params[lookat][1], i, n -> p(BigInt(n), params[lookat]...)) for i in 224:250 ]))

# ╔═╡ 364c5a36-8d90-11eb-3631-1bbaaedd9c88
function log_prob_more_than_0_seedexpander_calls(rand_size, param)
	p_0_sexp = P(rand_size, param...)
	convert(Float64, log2(1 - p_0_sexp^3))
end

# ╔═╡ 4ee028fc-8d90-11eb-2567-7149be250b5e
function find_suitable_rand_size(param, security)
	rand_size = param[1]
	while log_prob_more_than_0_seedexpander_calls(rand_size, param) > -security
		rand_size += 1
	end
	rand_size
end

# ╔═╡ eb2a3116-8d91-11eb-1e32-fd5372ad15aa
begin
	rand_sizes = [find_suitable_rand_size(param, security) for (param, security) in zip(params, params_SECURITY)]
	
	rand_sizes_ps1 = [find_suitable_rand_size((param[1:2]..., BigInt(1)//1), security) for (param, security) in zip(params, params_SECURITY)]
rsdf = DataFrame(alias=vec(params_NAMES), rand_size=rand_sizes, prob_more_than_0_sexp=map(zip(rand_sizes,params)) do (rand_size, param)
	log_prob_more_than_0_seedexpander_calls(rand_size, param)
		end, 
	rand_sizes_ps1 = rand_sizes_ps1,
	prob_more_than_0_sexp_ps1=map(zip(rand_sizes_ps1,params)) do (rand_size, param)
	log_prob_more_than_0_seedexpander_calls(rand_size, (param[1:2]..., BigInt(1)//1))
	end)
	println(latexify(rsdf, env=:tabular))
	rsdf
end

# ╔═╡ 42432018-6720-11eb-2522-576466c3b336
p4s = collect([convert(Float64, log2(1 - sum(p_dice(3, 0:3, i, n -> f(n, param...)) for i in 0:3))) for param=params]) # log2 probability that a message has 4 or more seed expander calls for each parameter set

# ╔═╡ 7d4b75ba-6721-11eb-3927-cf42b97d94bb
p4se = map(zip(params_K, p4s)) do (k, x)
	log2(1-big"2"^(big"2"^k * log2(1-big"2"^BigFloat(x))))
end # log2 probability of a message with 4 or more seed expander calls existing

# ╔═╡ bfca969e-7b32-11eb-0008-051ab09cbb6d
p_eq_3_s = collect([convert(Float64, p_dice(3, 0:3, 3, n -> f(n, param...))) for param=params]) # log2 probability that a message has 4 or more seed expander calls for each parameter set

# ╔═╡ 496cddc8-7ab4-11eb-38ae-db0abefb3c63
p4sdf = DataFrame( # tab:prob_4_seedexp
	name=vec(params_NAMES),
	k=params_K,
	p_eq_3_s=percentify.(p_eq_3_s),
	logp4s=convert.(Int64, round.(p4s)),
	logp4se=convert.(Int64, round.(p4se)),
)

# ╔═╡ b9496760-7ab4-11eb-33c2-190d2090281b
tablify(p4sdf)

# ╔═╡ b31a969a-7b34-11eb-01cf-29f0fcdecc9f
peh = map(zip(params_N, params_WE, params_PBASE)) do (n, we, p)
	prod(p*(n-i)/n for i=0:we-1)
end

# ╔═╡ fda51510-7b33-11eb-1bc9-b31ae3d826df
approx_probs = DataFrame(
	name=vec(params_NAMES),
	n1n2=params_N1N2,
	n=params_N,
	we=params_WE,
	p=map(params_PBASE) do p
		"\$\\frac{$(convert(Int64, p * 2^24))}{2^{24}}\$"
	end,
	peh=percentify.(peh),
	pehinvcubed=percentify.((1 .- peh) .^ 3),
)

# ╔═╡ f07e7be8-7b34-11eb-0de6-a1587b901e37
tablify(approx_probs)

# ╔═╡ 5bf7896a-20e2-11eb-1ef3-f5418c947f4b
relative_probs(samples) = samples ./ sum(samples)

# ╔═╡ 85d90bfc-7aa4-11eb-24f3-cbe8745fd99d
lookat = 7

# ╔═╡ 2ba72784-4059-11eb-0ed3-97b900660b9f
convert(Float64, f(1, params[lookat]...))

# ╔═╡ 92c4e8f8-405d-11eb-1cb3-35f16e257f01
params[lookat]

# ╔═╡ efdaa06b-6913-4a67-a868-b866da0d6582
params[lookat]

# ╔═╡ 140e67ca-4c72-40ad-8fdf-362cb41a0370
plot([BigFloat(p_dice(3, 0:151, i, n -> p(n, params[lookat]...))) for i in 0:250])

# ╔═╡ ffb1fddb-36f7-4727-901c-52d0eef005f6
p(BigInt(75), params[lookat]...)

# ╔═╡ 95e22840-8d8b-11eb-1650-4dd17c95f644
begin
	rand_size = 99
	# Compute probability that 0 seedexpander calls are required
	# in a single vectrand call when the random buffer size 
	# is rand_size
	p_0_sexp = P(rand_size, params[lookat]...)
	# Compute the probability that any of the 3
	# vectrand invocations requires more than 0 iters
	convert(Float64, log2(1 - p_0_sexp^3))
	# Compute the probability that a message exists that 
	# has more than 0 seedexpander calls
	# convert(Float64, log2(1 - big"2"^(
	# 			(big"2"^params_K[lookat]) * log2(p_0_sexp^3)
	# 		)
	# 	)
	# )
end

# ╔═╡ c8d63538-20cc-11eb-3055-e337d9888873
p_4 = 1 - sum(p_dice(3, 0:3, i, n -> f(n, params[lookat]...)) for i in 0:3); # probability of an m with 4 or more seed expansions

# ╔═╡ 6cb9ebae-20d2-11eb-0157-4b842459dd01
log2(p_4)

# ╔═╡ 76e507cc-20d1-11eb-33ac-9535b43cd7c3
BigFloat(log2(1-big"2"^(big"2"^(32*8) * log2(1-p_4)))) # log2 of probability that an m with 4 seed expansions exists

# ╔═╡ 9273e80a-20e0-11eb-3a10-892db891414e
empiric_results = relative_probs([5500749, 3638131, 802602, 58518])
#Old HQC-RMRS-128 (2020-05-29) relative_probs([6362513, 3105155, 504717, 27615])

# ╔═╡ 9ed82b00-20cd-11eb-3b15-ad69a1036a56
p_detect = 1-BigFloat(p_dice(3, 0:3, 3, n -> f(n, params[lookat]...))) # probability of detecting decryption to a different message when using an m with 3 seed expansions

# ╔═╡ 2de9bff4-20e5-11eb-001b-176862e23321
p_detect - (1-BigFloat(f(1, params[lookat]...)^3)) # very small difference between actual detection probability and approximated one
# approximation: every vector sampling needs exactly 1 seed expansion:
# 1 + 1 + 1 = 3
# the other cases for exactly == 3 are
# 2 + 1 + 0 = 3 and its permutations
# 3 + 0 + 0 = 3 and its permutations

# ╔═╡ 1acb80ce-20e7-11eb-3945-7b6f12af5e8c
# But these are all negligible since the probability of a single vector sampling
# requiring 2 or more seedexpansions is super low
log2(f(2, params[lookat]...))

# ╔═╡ bd4af0e8-20cd-11eb-1ae9-07ece00561bb
log2(p_detect^(params_N1N2[lookat])) # log2 of probability of success for all bits in v
# see PARAM_N1N2

# ╔═╡ b3e36126-20e7-11eb-0067-657eacd71656
# expected number of errors
(1-p_detect) * params_N1N2[lookat]

# ╔═╡ 62a65f26-2122-11eb-1b30-f5f5a0292d01
BigFloat(f(1, params[lookat]...))

# ╔═╡ 96299cc4-20e0-11eb-1eae-7f22b658af5d
computed_results = [ BigFloat(p_dice(3, 0:3, i, n -> f(n, params[lookat]...))) for i in 0:3 ]

# ╔═╡ 8d8d4262-2f47-11eb-1f27-73f5339cb71a
function pd(x)
	p_succ = 30/766 #big"2"^-4
	if x == 1
		p_succ
	elseif x == 0
		1 - p_succ
	else
		0
	end
end

# ╔═╡ 9456ad90-20e2-11eb-1ecb-13c26a8fe52e
results = DataFrame(n=0:3, empiric=empiric_results, computed=computed_results, delta=computed_results.-empiric_results)

# ╔═╡ bf220918-405c-11eb-3803-21c39e634853
p0 = BigFloat(f(0, params[lookat]...))

# ╔═╡ c4792732-405c-11eb-1080-efd50719a24f
p1 = BigFloat(f(1, params[lookat]...)) # approximate

# ╔═╡ ff318b32-405c-11eb-1618-ad8e36683e05
1-p1-p0

# ╔═╡ c3f77f86-227f-11eb-0168-859dbca0988d
pgfplotsx()

# ╔═╡ 55e586e0-227b-11eb-2509-a1f61cc06253
groupedbar(0:3, [empiric_results computed_results], labels=["Empiric" "Computed"], c=["orange" "blue"], xlab="seedexpander calls", ylab="probability")

# ╔═╡ 57112934-227b-11eb-0acc-cffb01260741
savefig("seedexpander_calls_distribution.pdf")

# ╔═╡ 201f7f62-2504-11eb-13a5-7ffd8802499b
params

# ╔═╡ c16bbff0-5422-11eb-122c-d137df32a47e
[ BigFloat(p_dice(3, 0:3, i, n -> f(n, param...))) for i=0:3, param=params ]

# ╔═╡ 8c5117c0-24fc-11eb-31d9-b32e9546c787
plot([bar(0:3,  [ BigFloat(p_dice(3, 0:3, i, n -> f(n, param...))) for i=0:3 ], title="$(params_NAMES[i])", 
			#xlab="seedexpander calls", 
			#ylab="probability", 
			ylim=(0,0.7),
			legend=false) for (i, param) in enumerate(params) ]...)

# ╔═╡ e1a68cba-2f64-11eb-2fb7-fb09458771dd
savefig("seedexpander_calls_distribution_all.pdf")

# ╔═╡ ddf4130a-2503-11eb-1da1-f92f209d1522
#BigFloat(p_dice(3, 0:3, 3, n -> f(n, params[lookat]...)))

# ╔═╡ 8f2e35e0-251a-11eb-3907-0fdb2c90f0a0
maximum(abs.(empiric_results .- computed_results)) # error of empiric / computed

# ╔═╡ cc1c971e-250e-11eb-1bca-abde2c429ef5
[BigFloat((1-f(0, param...))^3)*100 for param in params]

# ╔═╡ 717aec34-3d2b-11eb-30a9-29802c31bc7a
md"Analyze the success probability for each parameter set"

# ╔═╡ adc56fe8-3d2d-11eb-3860-9d2749d7a2e3
B(n, k, p) = binomial(n, k) * p^k * (1-p)^(n-k)

# ╔═╡ 85e7fee8-3d2b-11eb-370e-bb4ddf33beb2
succ_prob(n1n2, n, p) = sum(B.(n, (div(n,2)+1):n, 1-BigFloat(p)))^n1n2

# ╔═╡ d2364b20-3d2d-11eb-36b9-d30cb0eced6f
# only 0:3 since if one of the dice is 3, the others can only be 0 to obtain 3
begin 
	params_pe = [BigFloat(p_dice(3, 0:3
			, 3, n -> f(n, param...))) for param=params ] 
end

# ╔═╡ fcf294c2-4527-11eb-199f-9f2ee330ea43
1 .- params_pe

# ╔═╡ c7d3e77c-3d30-11eb-19e0-0360202738c9
majority_ns = collect(3:2:25)

# ╔═╡ e0b4bfdc-3d30-11eb-03ff-bdfd7ca9e784
success_probs = [succ_prob(N, i, p) for i=majority_ns, (p, N)=zip(params_pe, params_N1N2)]

# ╔═╡ 9668e225-2234-4779-a331-ca54eb0efc86
success_probs[2,7]

# ╔═╡ b21531dc-3d2d-11eb-2125-43a24de2bd3b
#groupedbar(majority_ns, success_probs, labels=params_NAMES, xtick=majority_ns, xlabel="majority of N", ylabel="success probability")

# ╔═╡ 32eb41e6-3d35-11eb-1969-c769ec1cb1ed
begin
	plts = [
		bar(majority_ns, success_probs[:,i], title="$(name)", 
			#xlabel="N", 
			#ylabel="success prob.", 
			xticks=2 .^(1:5) .+ 1, legend=false, ylim=(0,1))
		for (i, name) in enumerate(params_NAMES)
		]
	plot(plts..., layout=length(params_NAMES))
end

# ╔═╡ 2f05898e-3d37-11eb-282a-b95aff4f452e
savefig("success_probabilities_majority.pdf")

# ╔═╡ db56bb60-3d32-11eb-3038-818d9d9738ac
#gr() #majority_ns, 1:4, convert.(Float64, success_probs)

# ╔═╡ ea6d96b8-5fd9-11eb-169d-295a53d42297
function p_block(i, o, w)
	pb = OffsetArray(zeros(w+1, w+1), 0:w, 0:w)
	pb[0,0] = 1
	max_inside = min(i, w)
	for ip=0:max_inside-1
		for op=0:w-ip-1
			p_inside_block = (i-ip)/(i+o-ip-op)
			p_outside_block = 1 - p_inside_block #(o-op)/(i+o-ip-op)
			pb[ip + 1, op] += pb[ip, op] * p_inside_block
			pb[ip, op + 1] += pb[ip, op] * p_outside_block
		end
	end
	pbdist = OffsetArray(zeros(max_inside+1), 0:max_inside)
	for ip in 0:max_inside
		pbdist[ip] = pb[ip, w-ip]
	end
	pbdist
end

# ╔═╡ 350837e2-5fe0-11eb-39f0-67e60a5ec7e5
p_block(4, 4, 2)

# ╔═╡ 46232d0e-6220-11eb-1273-099cebbaa23a
p_block2(i, o, w, x) = begin
	i = BigInt(i)
	o = BigInt(o)
	x = BigInt(x)
	binomial(i, x) * binomial(o, w - x) // binomial(o + i, w)
end

# ╔═╡ 34b354f6-5fe1-11eb-343e-c9b01ea8ba69
begin
	select = 1
	inside = params_N[select] - params_N1N2[select]
	outside = params_N1N2[select]
	weight = params_W[select]
	#max_inside = min(inside, weight)
	p_block(inside, outside, weight)[0:5]
end

# ╔═╡ 7f60dda2-6220-11eb-3719-ad2fb7e64b25
[convert(Float64, p_block2(inside, outside, weight, w)) for w in 0:min(weight, inside, 5)]

# ╔═╡ 2c56c5c0-5fe1-11eb-129b-87f2d28290f9
normalize(fit(Histogram, collect(sum(sample(1:(inside+outside), weight, replace=false) .<= inside) for _=1:10000), 0:5), mode=:probability).weights # Verify computed probabilities

# ╔═╡ 2d65597c-7a76-11eb-2a9a-7fbde60b116e
max_inside_set_bits = 2

# ╔═╡ a767800c-7a75-11eb-04ab-952c9b518603
pzs = DataFrame( # tab:hqc_params_diff
	name=vec(params_NAMES), 
	n1n2=params_N1N2,
	n=params_N, 
	w=params_W,
	inside=params_N .- params_N1N2,
	possiblities=[ sum(binomial(inside, i) for i in 0:max_inside_set_bits) for inside in params_N .- params_N1N2],
	pZ_eq_0=[percentify(p_block2(
				params_N[i] - params_N1N2[i],
				params_N1N2[i],
				params_W[i],
				0
			)) for i in 1:length(params_N)], pZ_leq_max_inside_set_bits=
	[percentify(sum(p_block2.(
				params_N[i] - params_N1N2[i],
				params_N1N2[i],
				params_W[i],
				0:max_inside_set_bits
			))) for i in 1:length(params_N)], )

# ╔═╡ dd7e92e4-5fda-11eb-35b6-81fcd9835ef1
begin
	max_show = 3
	plts2 = [
		bar(collect(0:max_show), 
			p_block2.(
				params_N[i] - params_N1N2[i],
				params_N1N2[i],
				params_W[i],
				0:max_show
			),
			title="$(name)", # probability of N set bits
			#xlabel="N set bits",
			#ylabel="probability",
			xticks=0:max_show,
			legend=false,
			ylim=(0,1),
		)
		for (i, name) in enumerate(params_NAMES)
		]
	plot(plts2..., layout=length(params_NAMES))
end

# ╔═╡ cec51f1a-6233-11eb-084f-f7556abecc9e
[convert.(Float64, p_block2.(
				params_N[i] - params_N1N2[i],
				params_N1N2[i],
				params_W[i],
				0:max_show
			)) for i in 1:length(params_N)]

# ╔═╡ bddaf4a0-7922-11eb-04ef-3d30fe98b2be
convert.(Float64, p_block2.(
				params_N[1] - params_N1N2[1],
				params_N1N2[1],
				params_W[1],
				0:max_show
			))

# ╔═╡ 45e94934-5fde-11eb-39d9-67651b4de454
savefig("probability_outside_n1n2_bits.pdf")

# ╔═╡ e3887d1c-5fe4-11eb-1dbe-df46add45491
collect(zip(params_NAMES, [sum(p_block(
	params_N[i] - params_N1N2[i],
	params_N1N2[i],
	params_W[i]
						)[0:3]) for i=eachindex(params)]))

# ╔═╡ 414387d4-6239-11eb-114c-7136a6eb0277
collect(zip(params_NAMES, [convert(Float64, sum(p_block2.(
	params_N[i] - params_N1N2[i],
	params_N1N2[i],
	params_W[i], 0:3
						))) for i=eachindex(params)]))

# ╔═╡ b512dd28-5fe5-11eb-386a-530180aa7448
collect(zip(params_NAMES, [convert(Float64, p_block2(
	params_N[i] - params_N1N2[i],
	params_N1N2[i],
	params_W[i], 0
						)) for i=eachindex(params)]))

# ╔═╡ cda2cbd2-8e14-11eb-29e3-45aa278aaf60
tablify(pzs)

# ╔═╡ 9c92bc0b-42de-42e2-aa4e-4bc9ba4e61b4
pzs

# ╔═╡ 00000000-0000-0000-0000-000000000001
PLUTO_PROJECT_TOML_CONTENTS = """
[deps]
DataFrames = "a93c6f00-e57d-5684-b7b6-d8193f3e46c0"
Latexify = "23fbe1c1-3f47-55db-b15f-69d7ec21a316"
LinearAlgebra = "37e2e46d-f89d-539d-b4ee-838fcccc9c8e"
Memoize = "c03570c3-d221-55d1-a50c-7939bbd78826"
OffsetArrays = "6fe1bfb0-de20-5000-8ca7-80f57d26f881"
PGFPlotsX = "8314cec4-20b6-5062-9cdb-752b83310925"
Plots = "91a5bcdd-55d7-5caf-9e0b-520d859cae80"
StatsBase = "2913bbd2-ae8a-5f71-8c99-4fb6c76f3a91"
StatsPlots = "f3b207a7-027a-5e70-b257-86293d7955fd"

[compat]
DataFrames = "~1.2.0"
Latexify = "~0.15.6"
Memoize = "~0.4.4"
OffsetArrays = "~1.10.3"
PGFPlotsX = "~1.3.0"
Plots = "~1.19.2"
StatsBase = "~0.33.8"
StatsPlots = "~0.14.25"
"""

# ╔═╡ 00000000-0000-0000-0000-000000000002
PLUTO_MANIFEST_TOML_CONTENTS = """
# This file is machine-generated - editing it directly is not advised

[[AbstractFFTs]]
deps = ["LinearAlgebra"]
git-tree-sha1 = "485ee0867925449198280d4af84bdb46a2a404d0"
uuid = "621f4979-c628-5d54-868e-fcf4e3e8185c"
version = "1.0.1"

[[Adapt]]
deps = ["LinearAlgebra"]
git-tree-sha1 = "84918055d15b3114ede17ac6a7182f68870c16f7"
uuid = "79e6a3ab-5dfb-504d-930d-738a2a938a0e"
version = "3.3.1"

[[ArgCheck]]
git-tree-sha1 = "dedbbb2ddb876f899585c4ec4433265e3017215a"
uuid = "dce04be8-c92d-5529-be00-80e4d2c0e197"
version = "2.1.0"

[[ArgTools]]
uuid = "0dad84c5-d112-42e6-8d28-ef12dabb789f"

[[Arpack]]
deps = ["Arpack_jll", "Libdl", "LinearAlgebra"]
git-tree-sha1 = "2ff92b71ba1747c5fdd541f8fc87736d82f40ec9"
uuid = "7d9fca2a-8960-54d3-9f78-7d1dccf2cb97"
version = "0.4.0"

[[Arpack_jll]]
deps = ["Libdl", "OpenBLAS_jll", "Pkg"]
git-tree-sha1 = "e214a9b9bd1b4e1b4f15b22c0994862b66af7ff7"
uuid = "68821587-b530-5797-8361-c406ea357684"
version = "3.5.0+3"

[[Artifacts]]
uuid = "56f22d72-fd6d-98f1-02f0-08ddc0907c33"

[[AxisAlgorithms]]
deps = ["LinearAlgebra", "Random", "SparseArrays", "WoodburyMatrices"]
git-tree-sha1 = "a4d07a1c313392a77042855df46c5f534076fab9"
uuid = "13072b0f-2c55-5437-9ae7-d433b7a33950"
version = "1.0.0"

[[Base64]]
uuid = "2a0f44e3-6c83-55bd-87e4-b1978d98bd5f"

[[Bzip2_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "c3598e525718abcc440f69cc6d5f60dda0a1b61e"
uuid = "6e34b625-4abd-537c-b88f-471c36dfa7a0"
version = "1.0.6+5"

[[Cairo_jll]]
deps = ["Artifacts", "Bzip2_jll", "Fontconfig_jll", "FreeType2_jll", "Glib_jll", "JLLWrappers", "LZO_jll", "Libdl", "Pixman_jll", "Pkg", "Xorg_libXext_jll", "Xorg_libXrender_jll", "Zlib_jll", "libpng_jll"]
git-tree-sha1 = "e2f47f6d8337369411569fd45ae5753ca10394c6"
uuid = "83423d85-b0ee-5818-9007-b63ccbeb887a"
version = "1.16.0+6"

[[ChainRulesCore]]
deps = ["Compat", "LinearAlgebra", "SparseArrays"]
git-tree-sha1 = "f53ca8d41e4753c41cdafa6ec5f7ce914b34be54"
uuid = "d360d2e6-b24c-11e9-a2a3-2a2ae2dbcce4"
version = "0.10.13"

[[Clustering]]
deps = ["Distances", "LinearAlgebra", "NearestNeighbors", "Printf", "SparseArrays", "Statistics", "StatsBase"]
git-tree-sha1 = "75479b7df4167267d75294d14b58244695beb2ac"
uuid = "aaaa29a8-35af-508c-8bc3-b662a17a0fe5"
version = "0.14.2"

[[ColorSchemes]]
deps = ["ColorTypes", "Colors", "FixedPointNumbers", "Random", "StaticArrays"]
git-tree-sha1 = "ed268efe58512df8c7e224d2e170afd76dd6a417"
uuid = "35d6a980-a343-548e-a6ea-1d62b119f2f4"
version = "3.13.0"

[[ColorTypes]]
deps = ["FixedPointNumbers", "Random"]
git-tree-sha1 = "024fe24d83e4a5bf5fc80501a314ce0d1aa35597"
uuid = "3da002f7-5984-5a60-b8a6-cbb66c0b333f"
version = "0.11.0"

[[Colors]]
deps = ["ColorTypes", "FixedPointNumbers", "Reexport"]
git-tree-sha1 = "417b0ed7b8b838aa6ca0a87aadf1bb9eb111ce40"
uuid = "5ae59095-9a9b-59fe-a467-6f913c188581"
version = "0.12.8"

[[Compat]]
deps = ["Base64", "Dates", "DelimitedFiles", "Distributed", "InteractiveUtils", "LibGit2", "Libdl", "LinearAlgebra", "Markdown", "Mmap", "Pkg", "Printf", "REPL", "Random", "SHA", "Serialization", "SharedArrays", "Sockets", "SparseArrays", "Statistics", "Test", "UUIDs", "Unicode"]
git-tree-sha1 = "dc7dedc2c2aa9faf59a55c622760a25cbefbe941"
uuid = "34da2185-b29b-5c13-b0c7-acf172513d20"
version = "3.31.0"

[[CompilerSupportLibraries_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "e66e0078-7015-5450-92f7-15fbd957f2ae"

[[Contour]]
deps = ["StaticArrays"]
git-tree-sha1 = "9f02045d934dc030edad45944ea80dbd1f0ebea7"
uuid = "d38c429a-6771-53c6-b99e-75d170b6e991"
version = "0.5.7"

[[Crayons]]
git-tree-sha1 = "3f71217b538d7aaee0b69ab47d9b7724ca8afa0d"
uuid = "a8cc5b0e-0ffa-5ad4-8c14-923d3ee1735f"
version = "4.0.4"

[[DataAPI]]
git-tree-sha1 = "ee400abb2298bd13bfc3df1c412ed228061a2385"
uuid = "9a962f9c-6df0-11e9-0e5d-c546b8b5ee8a"
version = "1.7.0"

[[DataFrames]]
deps = ["Compat", "DataAPI", "Future", "InvertedIndices", "IteratorInterfaceExtensions", "LinearAlgebra", "Markdown", "Missings", "PooledArrays", "PrettyTables", "Printf", "REPL", "Reexport", "SortingAlgorithms", "Statistics", "TableTraits", "Tables", "Unicode"]
git-tree-sha1 = "1dadfca11c0e08e03ab15b63aaeda55266754bad"
uuid = "a93c6f00-e57d-5684-b7b6-d8193f3e46c0"
version = "1.2.0"

[[DataStructures]]
deps = ["Compat", "InteractiveUtils", "OrderedCollections"]
git-tree-sha1 = "4437b64df1e0adccc3e5d1adbc3ac741095e4677"
uuid = "864edb3b-99cc-5e75-8d2d-829cb0a9cfe8"
version = "0.18.9"

[[DataValueInterfaces]]
git-tree-sha1 = "bfc1187b79289637fa0ef6d4436ebdfe6905cbd6"
uuid = "e2d170a0-9d28-54be-80f0-106bbe20a464"
version = "1.0.0"

[[DataValues]]
deps = ["DataValueInterfaces", "Dates"]
git-tree-sha1 = "d88a19299eba280a6d062e135a43f00323ae70bf"
uuid = "e7dc6d0d-1eca-5fa6-8ad6-5aecde8b7ea5"
version = "0.4.13"

[[Dates]]
deps = ["Printf"]
uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"

[[DefaultApplication]]
deps = ["InteractiveUtils"]
git-tree-sha1 = "fc2b7122761b22c87fec8bf2ea4dc4563d9f8c24"
uuid = "3f0dd361-4fe0-5fc6-8523-80b14ec94d85"
version = "1.0.0"

[[DelimitedFiles]]
deps = ["Mmap"]
uuid = "8bb1440f-4735-579b-a4ab-409b98df4dab"

[[Distances]]
deps = ["LinearAlgebra", "Statistics", "StatsAPI"]
git-tree-sha1 = "abe4ad222b26af3337262b8afb28fab8d215e9f8"
uuid = "b4f34e82-e78d-54a5-968a-f98e89d6e8f7"
version = "0.10.3"

[[Distributed]]
deps = ["Random", "Serialization", "Sockets"]
uuid = "8ba89e20-285c-5b6f-9357-94700520ee1b"

[[Distributions]]
deps = ["FillArrays", "LinearAlgebra", "PDMats", "Printf", "QuadGK", "Random", "SparseArrays", "SpecialFunctions", "Statistics", "StatsBase", "StatsFuns"]
git-tree-sha1 = "3889f646423ce91dd1055a76317e9a1d3a23fff1"
uuid = "31c24e10-a181-5473-b8eb-7969acd0382f"
version = "0.25.11"

[[DocStringExtensions]]
deps = ["LibGit2"]
git-tree-sha1 = "a32185f5428d3986f47c2ab78b1f216d5e6cc96f"
uuid = "ffbed154-4ef7-542d-bbb7-c09d3a79fcae"
version = "0.8.5"

[[Downloads]]
deps = ["ArgTools", "LibCURL", "NetworkOptions"]
uuid = "f43a241f-c20a-4ad4-852c-f6b1247861c6"

[[EarCut_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "92d8f9f208637e8d2d28c664051a00569c01493d"
uuid = "5ae413db-bbd1-5e63-b57d-d24a61df00f5"
version = "2.1.5+1"

[[Expat_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "b3bfd02e98aedfa5cf885665493c5598c350cd2f"
uuid = "2e619515-83b5-522b-bb60-26c02a35a201"
version = "2.2.10+0"

[[FFMPEG]]
deps = ["FFMPEG_jll"]
git-tree-sha1 = "b57e3acbe22f8484b4b5ff66a7499717fe1a9cc8"
uuid = "c87230d0-a227-11e9-1b43-d7ebe4e7570a"
version = "0.4.1"

[[FFMPEG_jll]]
deps = ["Artifacts", "Bzip2_jll", "FreeType2_jll", "FriBidi_jll", "JLLWrappers", "LAME_jll", "LibVPX_jll", "Libdl", "Ogg_jll", "OpenSSL_jll", "Opus_jll", "Pkg", "Zlib_jll", "libass_jll", "libfdk_aac_jll", "libvorbis_jll", "x264_jll", "x265_jll"]
git-tree-sha1 = "3cc57ad0a213808473eafef4845a74766242e05f"
uuid = "b22a6f82-2f65-5046-a5b2-351ab43fb4e5"
version = "4.3.1+4"

[[FFTW]]
deps = ["AbstractFFTs", "FFTW_jll", "LinearAlgebra", "MKL_jll", "Preferences", "Reexport"]
git-tree-sha1 = "f985af3b9f4e278b1d24434cbb546d6092fca661"
uuid = "7a1cc6ca-52ef-59f5-83cd-3a7055c09341"
version = "1.4.3"

[[FFTW_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "3676abafff7e4ff07bbd2c42b3d8201f31653dcc"
uuid = "f5851436-0d7a-5f13-b9de-f02708fd171a"
version = "3.3.9+8"

[[FillArrays]]
deps = ["LinearAlgebra", "Random", "SparseArrays"]
git-tree-sha1 = "25b9cc23ba3303de0ad2eac03f840de9104c9253"
uuid = "1a297f60-69ca-5386-bcde-b61e274b549b"
version = "0.12.0"

[[FixedPointNumbers]]
deps = ["Statistics"]
git-tree-sha1 = "335bfdceacc84c5cdf16aadc768aa5ddfc5383cc"
uuid = "53c48c17-4a7d-5ca2-90c5-79b7896eea93"
version = "0.8.4"

[[Fontconfig_jll]]
deps = ["Artifacts", "Bzip2_jll", "Expat_jll", "FreeType2_jll", "JLLWrappers", "Libdl", "Libuuid_jll", "Pkg", "Zlib_jll"]
git-tree-sha1 = "35895cf184ceaab11fd778b4590144034a167a2f"
uuid = "a3f928ae-7b40-5064-980b-68af3947d34b"
version = "2.13.1+14"

[[Formatting]]
deps = ["Printf"]
git-tree-sha1 = "8339d61043228fdd3eb658d86c926cb282ae72a8"
uuid = "59287772-0a20-5a39-b81b-1366585eb4c0"
version = "0.4.2"

[[FreeType2_jll]]
deps = ["Artifacts", "Bzip2_jll", "JLLWrappers", "Libdl", "Pkg", "Zlib_jll"]
git-tree-sha1 = "cbd58c9deb1d304f5a245a0b7eb841a2560cfec6"
uuid = "d7e528f0-a631-5988-bf34-fe36492bcfd7"
version = "2.10.1+5"

[[FriBidi_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "aa31987c2ba8704e23c6c8ba8a4f769d5d7e4f91"
uuid = "559328eb-81f9-559d-9380-de523a88c83c"
version = "1.0.10+0"

[[Future]]
deps = ["Random"]
uuid = "9fa8497b-333b-5362-9e8d-4d0656e87820"

[[GLFW_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Libglvnd_jll", "Pkg", "Xorg_libXcursor_jll", "Xorg_libXi_jll", "Xorg_libXinerama_jll", "Xorg_libXrandr_jll"]
git-tree-sha1 = "0c603255764a1fa0b61752d2bec14cfbd18f7fe8"
uuid = "0656b61e-2033-5cc2-a64a-77c0f6c09b89"
version = "3.3.5+1"

[[GR]]
deps = ["Base64", "DelimitedFiles", "GR_jll", "HTTP", "JSON", "Libdl", "LinearAlgebra", "Pkg", "Printf", "Random", "Serialization", "Sockets", "Test", "UUIDs"]
git-tree-sha1 = "9f473cdf6e2eb360c576f9822e7c765dd9d26dbc"
uuid = "28b8d3ca-fb5f-59d9-8090-bfdbd6d07a71"
version = "0.58.0"

[[GR_jll]]
deps = ["Artifacts", "Bzip2_jll", "Cairo_jll", "FFMPEG_jll", "Fontconfig_jll", "GLFW_jll", "JLLWrappers", "JpegTurbo_jll", "Libdl", "Libtiff_jll", "Pixman_jll", "Pkg", "Qt5Base_jll", "Zlib_jll", "libpng_jll"]
git-tree-sha1 = "eaf96e05a880f3db5ded5a5a8a7817ecba3c7392"
uuid = "d2c73de3-f751-5644-a686-071e5b155ba9"
version = "0.58.0+0"

[[GeometryBasics]]
deps = ["EarCut_jll", "IterTools", "LinearAlgebra", "StaticArrays", "StructArrays", "Tables"]
git-tree-sha1 = "15ff9a14b9e1218958d3530cc288cf31465d9ae2"
uuid = "5c1252a2-5f33-56bf-86c9-59e7332b4326"
version = "0.3.13"

[[Gettext_jll]]
deps = ["Artifacts", "CompilerSupportLibraries_jll", "JLLWrappers", "Libdl", "Libiconv_jll", "Pkg", "XML2_jll"]
git-tree-sha1 = "9b02998aba7bf074d14de89f9d37ca24a1a0b046"
uuid = "78b55507-aeef-58d4-861c-77aaff3498b1"
version = "0.21.0+0"

[[Glib_jll]]
deps = ["Artifacts", "Gettext_jll", "JLLWrappers", "Libdl", "Libffi_jll", "Libiconv_jll", "Libmount_jll", "PCRE_jll", "Pkg", "Zlib_jll"]
git-tree-sha1 = "47ce50b742921377301e15005c96e979574e130b"
uuid = "7746bdde-850d-59dc-9ae8-88ece973131d"
version = "2.68.1+0"

[[Grisu]]
git-tree-sha1 = "53bb909d1151e57e2484c3d1b53e19552b887fb2"
uuid = "42e2da0e-8278-4e71-bc24-59509adca0fe"
version = "1.0.2"

[[HTTP]]
deps = ["Base64", "Dates", "IniFile", "Logging", "MbedTLS", "NetworkOptions", "Sockets", "URIs"]
git-tree-sha1 = "c6a1fff2fd4b1da29d3dccaffb1e1001244d844e"
uuid = "cd3eb016-35fb-5094-929b-558a96fad6f3"
version = "0.9.12"

[[IniFile]]
deps = ["Test"]
git-tree-sha1 = "098e4d2c533924c921f9f9847274f2ad89e018b8"
uuid = "83e8ac13-25f8-5344-8a64-a9f2b223428f"
version = "0.5.0"

[[IntelOpenMP_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "d979e54b71da82f3a65b62553da4fc3d18c9004c"
uuid = "1d5cc7b8-4909-519e-a0f8-d0f5ad9712d0"
version = "2018.0.3+2"

[[InteractiveUtils]]
deps = ["Markdown"]
uuid = "b77e0a4c-d291-57a0-90e8-8db25a27a240"

[[Interpolations]]
deps = ["AxisAlgorithms", "ChainRulesCore", "LinearAlgebra", "OffsetArrays", "Random", "Ratios", "Requires", "SharedArrays", "SparseArrays", "StaticArrays", "WoodburyMatrices"]
git-tree-sha1 = "1470c80592cf1f0a35566ee5e93c5f8221ebc33a"
uuid = "a98d9a8b-a2ab-59e6-89dd-64a1c18fca59"
version = "0.13.3"

[[InvertedIndices]]
deps = ["Test"]
git-tree-sha1 = "15732c475062348b0165684ffe28e85ea8396afc"
uuid = "41ab1584-1d38-5bbf-9106-f11c6c58b48f"
version = "1.0.0"

[[IterTools]]
git-tree-sha1 = "05110a2ab1fc5f932622ffea2a003221f4782c18"
uuid = "c8e1da08-722c-5040-9ed9-7db0dc04731e"
version = "1.3.0"

[[IteratorInterfaceExtensions]]
git-tree-sha1 = "a3f24677c21f5bbe9d2a714f95dcd58337fb2856"
uuid = "82899510-4779-5014-852e-03e436cf321d"
version = "1.0.0"

[[JLLWrappers]]
deps = ["Preferences"]
git-tree-sha1 = "642a199af8b68253517b80bd3bfd17eb4e84df6e"
uuid = "692b3bcd-3c85-4b1f-b108-f13ce0eb3210"
version = "1.3.0"

[[JSON]]
deps = ["Dates", "Mmap", "Parsers", "Unicode"]
git-tree-sha1 = "81690084b6198a2e1da36fcfda16eeca9f9f24e4"
uuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
version = "0.21.1"

[[JpegTurbo_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "d735490ac75c5cb9f1b00d8b5509c11984dc6943"
uuid = "aacddb02-875f-59d6-b918-886e6ef4fbf8"
version = "2.1.0+0"

[[KernelDensity]]
deps = ["Distributions", "DocStringExtensions", "FFTW", "Interpolations", "StatsBase"]
git-tree-sha1 = "591e8dc09ad18386189610acafb970032c519707"
uuid = "5ab0869b-81aa-558d-bb23-cbf5423bbe9b"
version = "0.6.3"

[[LAME_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "f6250b16881adf048549549fba48b1161acdac8c"
uuid = "c1c5ebd0-6772-5130-a774-d5fcae4a789d"
version = "3.100.1+0"

[[LZO_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "e5b909bcf985c5e2605737d2ce278ed791b89be6"
uuid = "dd4b983a-f0e5-5f8d-a1b7-129d4a5fb1ac"
version = "2.10.1+0"

[[LaTeXStrings]]
git-tree-sha1 = "c7f1c695e06c01b95a67f0cd1d34994f3e7db104"
uuid = "b964fa9f-0449-5b57-a5c2-d3ea65f4040f"
version = "1.2.1"

[[Latexify]]
deps = ["Formatting", "InteractiveUtils", "LaTeXStrings", "MacroTools", "Markdown", "Printf", "Requires"]
git-tree-sha1 = "a4b12a1bd2ebade87891ab7e36fdbce582301a92"
uuid = "23fbe1c1-3f47-55db-b15f-69d7ec21a316"
version = "0.15.6"

[[LazyArtifacts]]
deps = ["Artifacts", "Pkg"]
uuid = "4af54fe1-eca0-43a8-85a7-787d91b784e3"

[[LibCURL]]
deps = ["LibCURL_jll", "MozillaCACerts_jll"]
uuid = "b27032c2-a3e7-50c8-80cd-2d36dbcbfd21"

[[LibCURL_jll]]
deps = ["Artifacts", "LibSSH2_jll", "Libdl", "MbedTLS_jll", "Zlib_jll", "nghttp2_jll"]
uuid = "deac9b47-8bc7-5906-a0fe-35ac56dc84c0"

[[LibGit2]]
deps = ["Base64", "NetworkOptions", "Printf", "SHA"]
uuid = "76f85450-5226-5b5a-8eaa-529ad045b433"

[[LibSSH2_jll]]
deps = ["Artifacts", "Libdl", "MbedTLS_jll"]
uuid = "29816b5a-b9ab-546f-933c-edad1886dfa8"

[[LibVPX_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "12ee7e23fa4d18361e7c2cde8f8337d4c3101bc7"
uuid = "dd192d2f-8180-539f-9fb4-cc70b1dcf69a"
version = "1.10.0+0"

[[Libdl]]
uuid = "8f399da3-3557-5675-b5ff-fb832c97cbdb"

[[Libffi_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "0b4a5d71f3e5200a7dff793393e09dfc2d874290"
uuid = "e9f186c6-92d2-5b65-8a66-fee21dc1b490"
version = "3.2.2+1"

[[Libgcrypt_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Libgpg_error_jll", "Pkg"]
git-tree-sha1 = "64613c82a59c120435c067c2b809fc61cf5166ae"
uuid = "d4300ac3-e22c-5743-9152-c294e39db1e4"
version = "1.8.7+0"

[[Libglvnd_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libX11_jll", "Xorg_libXext_jll"]
git-tree-sha1 = "7739f837d6447403596a75d19ed01fd08d6f56bf"
uuid = "7e76a0d4-f3c7-5321-8279-8d96eeed0f29"
version = "1.3.0+3"

[[Libgpg_error_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "c333716e46366857753e273ce6a69ee0945a6db9"
uuid = "7add5ba3-2f88-524e-9cd5-f83b8a55f7b8"
version = "1.42.0+0"

[[Libiconv_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "42b62845d70a619f063a7da093d995ec8e15e778"
uuid = "94ce4f54-9a6c-5748-9c1c-f9c7231a4531"
version = "1.16.1+1"

[[Libmount_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "9c30530bf0effd46e15e0fdcf2b8636e78cbbd73"
uuid = "4b2f31a3-9ecc-558c-b454-b3730dcb73e9"
version = "2.35.0+0"

[[Libtiff_jll]]
deps = ["Artifacts", "JLLWrappers", "JpegTurbo_jll", "Libdl", "Pkg", "Zlib_jll", "Zstd_jll"]
git-tree-sha1 = "340e257aada13f95f98ee352d316c3bed37c8ab9"
uuid = "89763e89-9b03-5906-acba-b20f662cd828"
version = "4.3.0+0"

[[Libuuid_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "7f3efec06033682db852f8b3bc3c1d2b0a0ab066"
uuid = "38a345b3-de98-5d2b-a5d3-14cd9215e700"
version = "2.36.0+0"

[[LinearAlgebra]]
deps = ["Libdl"]
uuid = "37e2e46d-f89d-539d-b4ee-838fcccc9c8e"

[[LogExpFunctions]]
deps = ["DocStringExtensions", "LinearAlgebra"]
git-tree-sha1 = "7bd5f6565d80b6bf753738d2bc40a5dfea072070"
uuid = "2ab3a3ac-af41-5b50-aa03-7779005ae688"
version = "0.2.5"

[[Logging]]
uuid = "56ddb016-857b-54e1-b83d-db4d58db5568"

[[MKL_jll]]
deps = ["Artifacts", "IntelOpenMP_jll", "JLLWrappers", "LazyArtifacts", "Libdl", "Pkg"]
git-tree-sha1 = "5455aef09b40e5020e1520f551fa3135040d4ed0"
uuid = "856f044c-d86e-5d09-b602-aeab76dc8ba7"
version = "2021.1.1+2"

[[MacroTools]]
deps = ["Markdown", "Random"]
git-tree-sha1 = "6a8a2a625ab0dea913aba95c11370589e0239ff0"
uuid = "1914dd2f-81c6-5fcd-8719-6d5c9610ff09"
version = "0.5.6"

[[Markdown]]
deps = ["Base64"]
uuid = "d6f4376e-aef5-505a-96c1-9c027394607a"

[[MbedTLS]]
deps = ["Dates", "MbedTLS_jll", "Random", "Sockets"]
git-tree-sha1 = "1c38e51c3d08ef2278062ebceade0e46cefc96fe"
uuid = "739be429-bea8-5141-9913-cc70e7f3736d"
version = "1.0.3"

[[MbedTLS_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "c8ffd9c3-330d-5841-b78e-0817d7145fa1"

[[Measures]]
git-tree-sha1 = "e498ddeee6f9fdb4551ce855a46f54dbd900245f"
uuid = "442fdcdd-2543-5da2-b0f3-8c86c306513e"
version = "0.3.1"

[[Memoize]]
deps = ["MacroTools"]
git-tree-sha1 = "2b1dfcba103de714d31c033b5dacc2e4a12c7caa"
uuid = "c03570c3-d221-55d1-a50c-7939bbd78826"
version = "0.4.4"

[[Missings]]
deps = ["DataAPI"]
git-tree-sha1 = "4ea90bd5d3985ae1f9a908bd4500ae88921c5ce7"
uuid = "e1d29d7a-bbdc-5cf2-9ac0-f12de2c33e28"
version = "1.0.0"

[[Mmap]]
uuid = "a63ad114-7e13-5084-954f-fe012c677804"

[[MozillaCACerts_jll]]
uuid = "14a3606d-f60d-562e-9121-12d972cd8159"

[[MultivariateStats]]
deps = ["Arpack", "LinearAlgebra", "SparseArrays", "Statistics", "StatsBase"]
git-tree-sha1 = "8d958ff1854b166003238fe191ec34b9d592860a"
uuid = "6f286f6a-111f-5878-ab1e-185364afe411"
version = "0.8.0"

[[NaNMath]]
git-tree-sha1 = "bfe47e760d60b82b66b61d2d44128b62e3a369fb"
uuid = "77ba4419-2d1f-58cd-9bb1-8ffee604a2e3"
version = "0.3.5"

[[NearestNeighbors]]
deps = ["Distances", "StaticArrays"]
git-tree-sha1 = "16baacfdc8758bc374882566c9187e785e85c2f0"
uuid = "b8a86587-4115-5ab1-83bc-aa920d37bbce"
version = "0.4.9"

[[NetworkOptions]]
uuid = "ca575930-c2e3-43a9-ace4-1e988b2c1908"

[[Observables]]
git-tree-sha1 = "fe29afdef3d0c4a8286128d4e45cc50621b1e43d"
uuid = "510215fc-4207-5dde-b226-833fc4488ee2"
version = "0.4.0"

[[OffsetArrays]]
deps = ["Adapt"]
git-tree-sha1 = "4f825c6da64aebaa22cc058ecfceed1ab9af1c7e"
uuid = "6fe1bfb0-de20-5000-8ca7-80f57d26f881"
version = "1.10.3"

[[Ogg_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "7937eda4681660b4d6aeeecc2f7e1c81c8ee4e2f"
uuid = "e7412a2a-1a6e-54c0-be00-318e2571c051"
version = "1.3.5+0"

[[OpenBLAS_jll]]
deps = ["Artifacts", "CompilerSupportLibraries_jll", "Libdl"]
uuid = "4536629a-c528-5b80-bd46-f80d51c5b363"

[[OpenSSL_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "15003dcb7d8db3c6c857fda14891a539a8f2705a"
uuid = "458c3c95-2e84-50aa-8efc-19380b2a3a95"
version = "1.1.10+0"

[[OpenSpecFun_jll]]
deps = ["Artifacts", "CompilerSupportLibraries_jll", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "13652491f6856acfd2db29360e1bbcd4565d04f1"
uuid = "efe28fd5-8261-553b-a9e1-b2916fc3738e"
version = "0.5.5+0"

[[Opus_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "51a08fb14ec28da2ec7a927c4337e4332c2a4720"
uuid = "91d4177d-7536-5919-b921-800302f37372"
version = "1.3.2+0"

[[OrderedCollections]]
git-tree-sha1 = "85f8e6578bf1f9ee0d11e7bb1b1456435479d47c"
uuid = "bac558e1-5e72-5ebc-8fee-abe8a469f55d"
version = "1.4.1"

[[PCRE_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "b2a7af664e098055a7529ad1a900ded962bca488"
uuid = "2f80f16e-611a-54ab-bc61-aa92de5b98fc"
version = "8.44.0+0"

[[PDMats]]
deps = ["LinearAlgebra", "SparseArrays", "SuiteSparse"]
git-tree-sha1 = "4dd403333bcf0909341cfe57ec115152f937d7d8"
uuid = "90014a1f-27ba-587c-ab20-58faa44d9150"
version = "0.11.1"

[[PGFPlotsX]]
deps = ["ArgCheck", "DataStructures", "Dates", "DefaultApplication", "DocStringExtensions", "MacroTools", "Parameters", "Requires", "Tables"]
git-tree-sha1 = "c1ad96f4c7b707699929bed58b117b221b963642"
uuid = "8314cec4-20b6-5062-9cdb-752b83310925"
version = "1.3.0"

[[Parameters]]
deps = ["OrderedCollections", "UnPack"]
git-tree-sha1 = "2276ac65f1e236e0a6ea70baff3f62ad4c625345"
uuid = "d96e819e-fc66-5662-9728-84c9c7592b0a"
version = "0.12.2"

[[Parsers]]
deps = ["Dates"]
git-tree-sha1 = "c8abc88faa3f7a3950832ac5d6e690881590d6dc"
uuid = "69de0a69-1ddd-5017-9359-2bf0b02dc9f0"
version = "1.1.0"

[[Pixman_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "b4f5d02549a10e20780a24fce72bea96b6329e29"
uuid = "30392449-352a-5448-841d-b1acce4e97dc"
version = "0.40.1+0"

[[Pkg]]
deps = ["Artifacts", "Dates", "Downloads", "LibGit2", "Libdl", "Logging", "Markdown", "Printf", "REPL", "Random", "SHA", "Serialization", "TOML", "Tar", "UUIDs", "p7zip_jll"]
uuid = "44cfe95a-1eb2-52ea-b672-e2afdf69b78f"

[[PlotThemes]]
deps = ["PlotUtils", "Requires", "Statistics"]
git-tree-sha1 = "a3a964ce9dc7898193536002a6dd892b1b5a6f1d"
uuid = "ccf2f8ad-2431-5c83-bf29-c5338b663b6a"
version = "2.0.1"

[[PlotUtils]]
deps = ["ColorSchemes", "Colors", "Dates", "Printf", "Random", "Reexport", "Statistics"]
git-tree-sha1 = "501c20a63a34ac1d015d5304da0e645f42d91c9f"
uuid = "995b91a9-d308-5afd-9ec6-746e21dbc043"
version = "1.0.11"

[[Plots]]
deps = ["Base64", "Contour", "Dates", "FFMPEG", "FixedPointNumbers", "GR", "GeometryBasics", "JSON", "Latexify", "LinearAlgebra", "Measures", "NaNMath", "PlotThemes", "PlotUtils", "Printf", "REPL", "Random", "RecipesBase", "RecipesPipeline", "Reexport", "Requires", "Scratch", "Showoff", "SparseArrays", "Statistics", "StatsBase", "UUIDs"]
git-tree-sha1 = "f3d4d35b8cb87adc844c05c722f505776ac29988"
uuid = "91a5bcdd-55d7-5caf-9e0b-520d859cae80"
version = "1.19.2"

[[PooledArrays]]
deps = ["DataAPI", "Future"]
git-tree-sha1 = "cde4ce9d6f33219465b55162811d8de8139c0414"
uuid = "2dfb63ee-cc39-5dd5-95bd-886bf059d720"
version = "1.2.1"

[[Preferences]]
deps = ["TOML"]
git-tree-sha1 = "00cfd92944ca9c760982747e9a1d0d5d86ab1e5a"
uuid = "21216c6a-2e73-6563-6e65-726566657250"
version = "1.2.2"

[[PrettyTables]]
deps = ["Crayons", "Formatting", "Markdown", "Reexport", "Tables"]
git-tree-sha1 = "0d1245a357cc61c8cd61934c07447aa569ff22e6"
uuid = "08abe8d2-0d0c-5749-adfa-8a2ac140af0d"
version = "1.1.0"

[[Printf]]
deps = ["Unicode"]
uuid = "de0858da-6303-5e67-8744-51eddeeeb8d7"

[[Qt5Base_jll]]
deps = ["Artifacts", "CompilerSupportLibraries_jll", "Fontconfig_jll", "Glib_jll", "JLLWrappers", "Libdl", "Libglvnd_jll", "OpenSSL_jll", "Pkg", "Xorg_libXext_jll", "Xorg_libxcb_jll", "Xorg_xcb_util_image_jll", "Xorg_xcb_util_keysyms_jll", "Xorg_xcb_util_renderutil_jll", "Xorg_xcb_util_wm_jll", "Zlib_jll", "xkbcommon_jll"]
git-tree-sha1 = "ad368663a5e20dbb8d6dc2fddeefe4dae0781ae8"
uuid = "ea2cea3b-5b76-57ae-a6ef-0a8af62496e1"
version = "5.15.3+0"

[[QuadGK]]
deps = ["DataStructures", "LinearAlgebra"]
git-tree-sha1 = "12fbe86da16df6679be7521dfb39fbc861e1dc7b"
uuid = "1fd47b50-473d-5c70-9696-f719f8f3bcdc"
version = "2.4.1"

[[REPL]]
deps = ["InteractiveUtils", "Markdown", "Sockets", "Unicode"]
uuid = "3fa0cd96-eef1-5676-8a61-b3b8758bbffb"

[[Random]]
deps = ["Serialization"]
uuid = "9a3f8284-a2c9-5f02-9a11-845980a1fd5c"

[[Ratios]]
git-tree-sha1 = "37d210f612d70f3f7d57d488cb3b6eff56ad4e41"
uuid = "c84ed2f1-dad5-54f0-aa8e-dbefe2724439"
version = "0.4.0"

[[RecipesBase]]
git-tree-sha1 = "b3fb709f3c97bfc6e948be68beeecb55a0b340ae"
uuid = "3cdcf5f2-1ef4-517c-9805-6587b60abb01"
version = "1.1.1"

[[RecipesPipeline]]
deps = ["Dates", "NaNMath", "PlotUtils", "RecipesBase"]
git-tree-sha1 = "2a7a2469ed5d94a98dea0e85c46fa653d76be0cd"
uuid = "01d81517-befc-4cb6-b9ec-a95719d0359c"
version = "0.3.4"

[[Reexport]]
git-tree-sha1 = "5f6c21241f0f655da3952fd60aa18477cf96c220"
uuid = "189a3867-3050-52da-a836-e630ba90ab69"
version = "1.1.0"

[[Requires]]
deps = ["UUIDs"]
git-tree-sha1 = "4036a3bd08ac7e968e27c203d45f5fff15020621"
uuid = "ae029012-a4dd-5104-9daa-d747884805df"
version = "1.1.3"

[[Rmath]]
deps = ["Random", "Rmath_jll"]
git-tree-sha1 = "bf3188feca147ce108c76ad82c2792c57abe7b1f"
uuid = "79098fc4-a85e-5d69-aa6a-4863f24498fa"
version = "0.7.0"

[[Rmath_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "68db32dff12bb6127bac73c209881191bf0efbb7"
uuid = "f50d1b31-88e8-58de-be2c-1cc44531875f"
version = "0.3.0+0"

[[SHA]]
uuid = "ea8e919c-243c-51af-8825-aaa63cd721ce"

[[Scratch]]
deps = ["Dates"]
git-tree-sha1 = "0b4b7f1393cff97c33891da2a0bf69c6ed241fda"
uuid = "6c6a2e73-6563-6170-7368-637461726353"
version = "1.1.0"

[[SentinelArrays]]
deps = ["Dates", "Random"]
git-tree-sha1 = "ffae887d0f0222a19c406a11c3831776d1383e3d"
uuid = "91c51154-3ec4-41a3-a24f-3f23e20d615c"
version = "1.3.3"

[[Serialization]]
uuid = "9e88b42a-f829-5b0c-bbe9-9e923198166b"

[[SharedArrays]]
deps = ["Distributed", "Mmap", "Random", "Serialization"]
uuid = "1a1011a3-84de-559e-8e89-a11a2f7dc383"

[[Showoff]]
deps = ["Dates", "Grisu"]
git-tree-sha1 = "91eddf657aca81df9ae6ceb20b959ae5653ad1de"
uuid = "992d4aef-0814-514b-bc4d-f2e9a6c4116f"
version = "1.0.3"

[[Sockets]]
uuid = "6462fe0b-24de-5631-8697-dd941f90decc"

[[SortingAlgorithms]]
deps = ["DataStructures"]
git-tree-sha1 = "b3363d7460f7d098ca0912c69b082f75625d7508"
uuid = "a2af1166-a08f-5f64-846c-94a0d3cef48c"
version = "1.0.1"

[[SparseArrays]]
deps = ["LinearAlgebra", "Random"]
uuid = "2f01184e-e22b-5df5-ae63-d93ebab69eaf"

[[SpecialFunctions]]
deps = ["ChainRulesCore", "LogExpFunctions", "OpenSpecFun_jll"]
git-tree-sha1 = "a50550fa3164a8c46747e62063b4d774ac1bcf49"
uuid = "276daf66-3868-5448-9aa4-cd146d93841b"
version = "1.5.1"

[[StaticArrays]]
deps = ["LinearAlgebra", "Random", "Statistics"]
git-tree-sha1 = "1b9a0f17ee0adde9e538227de093467348992397"
uuid = "90137ffa-7385-5640-81b9-e52037218182"
version = "1.2.7"

[[Statistics]]
deps = ["LinearAlgebra", "SparseArrays"]
uuid = "10745b16-79ce-11e8-11f9-7d13ad32a3b2"

[[StatsAPI]]
git-tree-sha1 = "1958272568dc176a1d881acb797beb909c785510"
uuid = "82ae8749-77ed-4fe6-ae5f-f523153014b0"
version = "1.0.0"

[[StatsBase]]
deps = ["DataAPI", "DataStructures", "LinearAlgebra", "Missings", "Printf", "Random", "SortingAlgorithms", "SparseArrays", "Statistics", "StatsAPI"]
git-tree-sha1 = "2f6792d523d7448bbe2fec99eca9218f06cc746d"
uuid = "2913bbd2-ae8a-5f71-8c99-4fb6c76f3a91"
version = "0.33.8"

[[StatsFuns]]
deps = ["LogExpFunctions", "Rmath", "SpecialFunctions"]
git-tree-sha1 = "30cd8c360c54081f806b1ee14d2eecbef3c04c49"
uuid = "4c63d2b9-4356-54db-8cca-17b64c39e42c"
version = "0.9.8"

[[StatsPlots]]
deps = ["Clustering", "DataStructures", "DataValues", "Distributions", "Interpolations", "KernelDensity", "LinearAlgebra", "MultivariateStats", "Observables", "Plots", "RecipesBase", "RecipesPipeline", "Reexport", "StatsBase", "TableOperations", "Tables", "Widgets"]
git-tree-sha1 = "990daa9c943e7ee108a36ad17769bf3a51622875"
uuid = "f3b207a7-027a-5e70-b257-86293d7955fd"
version = "0.14.25"

[[StructArrays]]
deps = ["Adapt", "DataAPI", "StaticArrays", "Tables"]
git-tree-sha1 = "000e168f5cc9aded17b6999a560b7c11dda69095"
uuid = "09ab397b-f2b6-538f-b94a-2f83cf4a842a"
version = "0.6.0"

[[SuiteSparse]]
deps = ["Libdl", "LinearAlgebra", "Serialization", "SparseArrays"]
uuid = "4607b0f0-06f3-5cda-b6b1-a6196a1729e9"

[[TOML]]
deps = ["Dates"]
uuid = "fa267f1f-6049-4f14-aa54-33bafae1ed76"

[[TableOperations]]
deps = ["SentinelArrays", "Tables", "Test"]
git-tree-sha1 = "a7cf690d0ac3f5b53dd09b5d613540b230233647"
uuid = "ab02a1b2-a7df-11e8-156e-fb1833f50b87"
version = "1.0.0"

[[TableTraits]]
deps = ["IteratorInterfaceExtensions"]
git-tree-sha1 = "c06b2f539df1c6efa794486abfb6ed2022561a39"
uuid = "3783bdb8-4a98-5b6b-af9a-565f29a5fe9c"
version = "1.0.1"

[[Tables]]
deps = ["DataAPI", "DataValueInterfaces", "IteratorInterfaceExtensions", "LinearAlgebra", "TableTraits", "Test"]
git-tree-sha1 = "8ed4a3ea724dac32670b062be3ef1c1de6773ae8"
uuid = "bd369af6-aec1-5ad0-b16a-f7cc5008161c"
version = "1.4.4"

[[Tar]]
deps = ["ArgTools", "SHA"]
uuid = "a4e569a6-e804-4fa4-b0f3-eef7a1d5b13e"

[[Test]]
deps = ["InteractiveUtils", "Logging", "Random", "Serialization"]
uuid = "8dfed614-e22c-5e08-85e1-65c5234f0b40"

[[URIs]]
git-tree-sha1 = "97bbe755a53fe859669cd907f2d96aee8d2c1355"
uuid = "5c2747f8-b7ea-4ff2-ba2e-563bfd36b1d4"
version = "1.3.0"

[[UUIDs]]
deps = ["Random", "SHA"]
uuid = "cf7118a7-6976-5b1a-9a39-7adc72f591a4"

[[UnPack]]
git-tree-sha1 = "387c1f73762231e86e0c9c5443ce3b4a0a9a0c2b"
uuid = "3a884ed6-31ef-47d7-9d2a-63182c4928ed"
version = "1.0.2"

[[Unicode]]
uuid = "4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5"

[[Wayland_jll]]
deps = ["Artifacts", "Expat_jll", "JLLWrappers", "Libdl", "Libffi_jll", "Pkg", "XML2_jll"]
git-tree-sha1 = "3e61f0b86f90dacb0bc0e73a0c5a83f6a8636e23"
uuid = "a2964d1f-97da-50d4-b82a-358c7fce9d89"
version = "1.19.0+0"

[[Wayland_protocols_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Wayland_jll"]
git-tree-sha1 = "2839f1c1296940218e35df0bbb220f2a79686670"
uuid = "2381bf8a-dfd0-557d-9999-79630e7b1b91"
version = "1.18.0+4"

[[Widgets]]
deps = ["Colors", "Dates", "Observables", "OrderedCollections"]
git-tree-sha1 = "eae2fbbc34a79ffd57fb4c972b08ce50b8f6a00d"
uuid = "cc8bc4a8-27d6-5769-a93b-9d913e69aa62"
version = "0.6.3"

[[WoodburyMatrices]]
deps = ["LinearAlgebra", "SparseArrays"]
git-tree-sha1 = "59e2ad8fd1591ea019a5259bd012d7aee15f995c"
uuid = "efce3f68-66dc-5838-9240-27a6d6f5f9b6"
version = "0.5.3"

[[XML2_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Libiconv_jll", "Pkg", "Zlib_jll"]
git-tree-sha1 = "1acf5bdf07aa0907e0a37d3718bb88d4b687b74a"
uuid = "02c8fc9c-b97f-50b9-bbe4-9be30ff0a78a"
version = "2.9.12+0"

[[XSLT_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Libgcrypt_jll", "Libgpg_error_jll", "Libiconv_jll", "Pkg", "XML2_jll", "Zlib_jll"]
git-tree-sha1 = "91844873c4085240b95e795f692c4cec4d805f8a"
uuid = "aed1982a-8fda-507f-9586-7b0439959a61"
version = "1.1.34+0"

[[Xorg_libX11_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libxcb_jll", "Xorg_xtrans_jll"]
git-tree-sha1 = "5be649d550f3f4b95308bf0183b82e2582876527"
uuid = "4f6342f7-b3d2-589e-9d20-edeb45f2b2bc"
version = "1.6.9+4"

[[Xorg_libXau_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "4e490d5c960c314f33885790ed410ff3a94ce67e"
uuid = "0c0b7dd1-d40b-584c-a123-a41640f87eec"
version = "1.0.9+4"

[[Xorg_libXcursor_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libXfixes_jll", "Xorg_libXrender_jll"]
git-tree-sha1 = "12e0eb3bc634fa2080c1c37fccf56f7c22989afd"
uuid = "935fb764-8cf2-53bf-bb30-45bb1f8bf724"
version = "1.2.0+4"

[[Xorg_libXdmcp_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "4fe47bd2247248125c428978740e18a681372dd4"
uuid = "a3789734-cfe1-5b06-b2d0-1dd0d9d62d05"
version = "1.1.3+4"

[[Xorg_libXext_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libX11_jll"]
git-tree-sha1 = "b7c0aa8c376b31e4852b360222848637f481f8c3"
uuid = "1082639a-0dae-5f34-9b06-72781eeb8cb3"
version = "1.3.4+4"

[[Xorg_libXfixes_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libX11_jll"]
git-tree-sha1 = "0e0dc7431e7a0587559f9294aeec269471c991a4"
uuid = "d091e8ba-531a-589c-9de9-94069b037ed8"
version = "5.0.3+4"

[[Xorg_libXi_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libXext_jll", "Xorg_libXfixes_jll"]
git-tree-sha1 = "89b52bc2160aadc84d707093930ef0bffa641246"
uuid = "a51aa0fd-4e3c-5386-b890-e753decda492"
version = "1.7.10+4"

[[Xorg_libXinerama_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libXext_jll"]
git-tree-sha1 = "26be8b1c342929259317d8b9f7b53bf2bb73b123"
uuid = "d1454406-59df-5ea1-beac-c340f2130bc3"
version = "1.1.4+4"

[[Xorg_libXrandr_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libXext_jll", "Xorg_libXrender_jll"]
git-tree-sha1 = "34cea83cb726fb58f325887bf0612c6b3fb17631"
uuid = "ec84b674-ba8e-5d96-8ba1-2a689ba10484"
version = "1.5.2+4"

[[Xorg_libXrender_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libX11_jll"]
git-tree-sha1 = "19560f30fd49f4d4efbe7002a1037f8c43d43b96"
uuid = "ea2f1a96-1ddc-540d-b46f-429655e07cfa"
version = "0.9.10+4"

[[Xorg_libpthread_stubs_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "6783737e45d3c59a4a4c4091f5f88cdcf0908cbb"
uuid = "14d82f49-176c-5ed1-bb49-ad3f5cbd8c74"
version = "0.1.0+3"

[[Xorg_libxcb_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "XSLT_jll", "Xorg_libXau_jll", "Xorg_libXdmcp_jll", "Xorg_libpthread_stubs_jll"]
git-tree-sha1 = "daf17f441228e7a3833846cd048892861cff16d6"
uuid = "c7cfdc94-dc32-55de-ac96-5a1b8d977c5b"
version = "1.13.0+3"

[[Xorg_libxkbfile_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libX11_jll"]
git-tree-sha1 = "926af861744212db0eb001d9e40b5d16292080b2"
uuid = "cc61e674-0454-545c-8b26-ed2c68acab7a"
version = "1.1.0+4"

[[Xorg_xcb_util_image_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_xcb_util_jll"]
git-tree-sha1 = "0fab0a40349ba1cba2c1da699243396ff8e94b97"
uuid = "12413925-8142-5f55-bb0e-6d7ca50bb09b"
version = "0.4.0+1"

[[Xorg_xcb_util_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libxcb_jll"]
git-tree-sha1 = "e7fd7b2881fa2eaa72717420894d3938177862d1"
uuid = "2def613f-5ad1-5310-b15b-b15d46f528f5"
version = "0.4.0+1"

[[Xorg_xcb_util_keysyms_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_xcb_util_jll"]
git-tree-sha1 = "d1151e2c45a544f32441a567d1690e701ec89b00"
uuid = "975044d2-76e6-5fbe-bf08-97ce7c6574c7"
version = "0.4.0+1"

[[Xorg_xcb_util_renderutil_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_xcb_util_jll"]
git-tree-sha1 = "dfd7a8f38d4613b6a575253b3174dd991ca6183e"
uuid = "0d47668e-0667-5a69-a72c-f761630bfb7e"
version = "0.3.9+1"

[[Xorg_xcb_util_wm_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_xcb_util_jll"]
git-tree-sha1 = "e78d10aab01a4a154142c5006ed44fd9e8e31b67"
uuid = "c22f9ab0-d5fe-5066-847c-f4bb1cd4e361"
version = "0.4.1+1"

[[Xorg_xkbcomp_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_libxkbfile_jll"]
git-tree-sha1 = "4bcbf660f6c2e714f87e960a171b119d06ee163b"
uuid = "35661453-b289-5fab-8a00-3d9160c6a3a4"
version = "1.4.2+4"

[[Xorg_xkeyboard_config_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Xorg_xkbcomp_jll"]
git-tree-sha1 = "5c8424f8a67c3f2209646d4425f3d415fee5931d"
uuid = "33bec58e-1273-512f-9401-5d533626f822"
version = "2.27.0+4"

[[Xorg_xtrans_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "79c31e7844f6ecf779705fbc12146eb190b7d845"
uuid = "c5fb5394-a638-5e4d-96e5-b29de1b5cf10"
version = "1.4.0+3"

[[Zlib_jll]]
deps = ["Libdl"]
uuid = "83775a58-1f1d-513f-b197-d71354ab007a"

[[Zstd_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "cc4bf3fdde8b7e3e9fa0351bdeedba1cf3b7f6e6"
uuid = "3161d3a3-bdf6-5164-811a-617609db77b4"
version = "1.5.0+0"

[[libass_jll]]
deps = ["Artifacts", "Bzip2_jll", "FreeType2_jll", "FriBidi_jll", "JLLWrappers", "Libdl", "Pkg", "Zlib_jll"]
git-tree-sha1 = "acc685bcf777b2202a904cdcb49ad34c2fa1880c"
uuid = "0ac62f75-1d6f-5e53-bd7c-93b484bb37c0"
version = "0.14.0+4"

[[libfdk_aac_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "7a5780a0d9c6864184b3a2eeeb833a0c871f00ab"
uuid = "f638f0a6-7fb0-5443-88ba-1cc74229b280"
version = "0.1.6+4"

[[libpng_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Zlib_jll"]
git-tree-sha1 = "94d180a6d2b5e55e447e2d27a29ed04fe79eb30c"
uuid = "b53b4c65-9356-5827-b1ea-8c7a1a84506f"
version = "1.6.38+0"

[[libvorbis_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Ogg_jll", "Pkg"]
git-tree-sha1 = "c45f4e40e7aafe9d086379e5578947ec8b95a8fb"
uuid = "f27f6e37-5d2b-51aa-960f-b287f2bc3b7a"
version = "1.3.7+0"

[[nghttp2_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "8e850ede-7688-5339-a07c-302acd2aaf8d"

[[p7zip_jll]]
deps = ["Artifacts", "Libdl"]
uuid = "3f19e933-33d8-53b3-aaab-bd5110c3b7a0"

[[x264_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "d713c1ce4deac133e3334ee12f4adff07f81778f"
uuid = "1270edf5-f2f9-52d2-97e9-ab00b5d0237a"
version = "2020.7.14+2"

[[x265_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg"]
git-tree-sha1 = "487da2f8f2f0c8ee0e83f39d13037d6bbf0a45ab"
uuid = "dfaa095f-4041-5dcd-9319-2fabd8486b76"
version = "3.0.0+3"

[[xkbcommon_jll]]
deps = ["Artifacts", "JLLWrappers", "Libdl", "Pkg", "Wayland_jll", "Wayland_protocols_jll", "Xorg_libxcb_jll", "Xorg_xkeyboard_config_jll"]
git-tree-sha1 = "ece2350174195bb31de1a63bea3a41ae1aa593b6"
uuid = "d8fb68d0-12a3-5cfd-a85a-d49703b185fd"
version = "0.9.1+5"
"""

# ╔═╡ Cell order:
# ╠═f06458ee-7b37-11eb-1678-2b7ff63fd134
# ╠═015f8f92-7b38-11eb-0782-4f56419b6d75
# ╠═c999c71e-2081-11eb-08d0-394b8bacd1cb
# ╠═7c7f5616-2085-11eb-0c34-19e84a55912c
# ╠═e862dac6-44a5-11eb-0cd0-a717546aa912
# ╠═b07cb028-44a5-11eb-2515-ff56762cb362
# ╠═b240cd22-44a5-11eb-1d9b-43a2f61426f8
# ╠═d6230b46-3fbf-11eb-0eeb-1fc88a3f750f
# ╠═b54bc926-3ff6-11eb-1ca8-6330113eab6d
# ╠═baed15a6-3ff6-11eb-3169-494beb92dc53
# ╠═fa86d996-404f-11eb-16fc-d1294cbc2ad8
# ╠═2246bdb4-208b-11eb-15e8-350713fd42e9
# ╠═58cbf960-2088-11eb-3576-b77801d0ecae
# ╠═1d6febb8-2279-11eb-0411-e916df2e0da4
# ╠═2c71c9b8-208a-11eb-2334-794198d4fb63
# ╠═26d59634-2086-11eb-13b0-7dad3b1751fd
# ╠═5d151c74-20d1-11eb-2610-03d7bb5a5744
# ╠═9e401752-20d2-11eb-0336-f104e0d96d05
# ╠═46072f6c-24f8-11eb-3571-151e9ebeea63
# ╠═2ba72784-4059-11eb-0ed3-97b900660b9f
# ╠═92c4e8f8-405d-11eb-1cb3-35f16e257f01
# ╠═aaba6da0-405f-11eb-116c-933bd36e48b1
# ╠═d60c1128-2504-11eb-1da7-fd7d0be5b076
# ╠═db492024-24fd-11eb-0d28-53126b605321
# ╠═46f82718-20dd-11eb-317b-9710e5bb8aa0
# ╠═efdaa06b-6913-4a67-a868-b866da0d6582
# ╠═140e67ca-4c72-40ad-8fdf-362cb41a0370
# ╠═ffb1fddb-36f7-4727-901c-52d0eef005f6
# ╠═9f1b9ebd-daf0-4dbf-80d9-6bf6969afdbb
# ╠═95e22840-8d8b-11eb-1650-4dd17c95f644
# ╠═364c5a36-8d90-11eb-3631-1bbaaedd9c88
# ╠═4ee028fc-8d90-11eb-2567-7149be250b5e
# ╠═68aef322-8d9e-11eb-3a36-ab8de8bf8d4f
# ╠═eb2a3116-8d91-11eb-1e32-fd5372ad15aa
# ╠═c8d63538-20cc-11eb-3055-e337d9888873
# ╠═6cb9ebae-20d2-11eb-0157-4b842459dd01
# ╠═76e507cc-20d1-11eb-33ac-9535b43cd7c3
# ╠═42432018-6720-11eb-2522-576466c3b336
# ╠═7d4b75ba-6721-11eb-3927-cf42b97d94bb
# ╠═bfca969e-7b32-11eb-0008-051ab09cbb6d
# ╠═496cddc8-7ab4-11eb-38ae-db0abefb3c63
# ╠═b9496760-7ab4-11eb-33c2-190d2090281b
# ╠═b31a969a-7b34-11eb-01cf-29f0fcdecc9f
# ╠═fda51510-7b33-11eb-1bc9-b31ae3d826df
# ╠═f07e7be8-7b34-11eb-0de6-a1587b901e37
# ╠═5bf7896a-20e2-11eb-1ef3-f5418c947f4b
# ╠═85d90bfc-7aa4-11eb-24f3-cbe8745fd99d
# ╠═9273e80a-20e0-11eb-3a10-892db891414e
# ╠═9ed82b00-20cd-11eb-3b15-ad69a1036a56
# ╠═2de9bff4-20e5-11eb-001b-176862e23321
# ╠═1acb80ce-20e7-11eb-3945-7b6f12af5e8c
# ╠═bd4af0e8-20cd-11eb-1ae9-07ece00561bb
# ╠═b3e36126-20e7-11eb-0067-657eacd71656
# ╠═62a65f26-2122-11eb-1b30-f5f5a0292d01
# ╠═96299cc4-20e0-11eb-1eae-7f22b658af5d
# ╠═8d8d4262-2f47-11eb-1f27-73f5339cb71a
# ╠═6750687c-20e2-11eb-174d-7b428cdfee0d
# ╠═9456ad90-20e2-11eb-1ecb-13c26a8fe52e
# ╠═bf220918-405c-11eb-3803-21c39e634853
# ╠═c4792732-405c-11eb-1080-efd50719a24f
# ╠═ff318b32-405c-11eb-1618-ad8e36683e05
# ╠═a8259e8a-20e2-11eb-2257-edcf371886d4
# ╠═c3f77f86-227f-11eb-0168-859dbca0988d
# ╠═55e586e0-227b-11eb-2509-a1f61cc06253
# ╠═57112934-227b-11eb-0acc-cffb01260741
# ╠═201f7f62-2504-11eb-13a5-7ffd8802499b
# ╠═c16bbff0-5422-11eb-122c-d137df32a47e
# ╠═8c5117c0-24fc-11eb-31d9-b32e9546c787
# ╠═e1a68cba-2f64-11eb-2fb7-fb09458771dd
# ╠═ddf4130a-2503-11eb-1da1-f92f209d1522
# ╠═8f2e35e0-251a-11eb-3907-0fdb2c90f0a0
# ╠═cc1c971e-250e-11eb-1bca-abde2c429ef5
# ╟─717aec34-3d2b-11eb-30a9-29802c31bc7a
# ╠═85e7fee8-3d2b-11eb-370e-bb4ddf33beb2
# ╠═adc56fe8-3d2d-11eb-3860-9d2749d7a2e3
# ╠═d2364b20-3d2d-11eb-36b9-d30cb0eced6f
# ╠═fcf294c2-4527-11eb-199f-9f2ee330ea43
# ╠═c7d3e77c-3d30-11eb-19e0-0360202738c9
# ╠═e0b4bfdc-3d30-11eb-03ff-bdfd7ca9e784
# ╠═9668e225-2234-4779-a331-ca54eb0efc86
# ╠═b21531dc-3d2d-11eb-2125-43a24de2bd3b
# ╠═32eb41e6-3d35-11eb-1969-c769ec1cb1ed
# ╠═2f05898e-3d37-11eb-282a-b95aff4f452e
# ╠═db56bb60-3d32-11eb-3038-818d9d9738ac
# ╠═ea6d96b8-5fd9-11eb-169d-295a53d42297
# ╠═350837e2-5fe0-11eb-39f0-67e60a5ec7e5
# ╠═46232d0e-6220-11eb-1273-099cebbaa23a
# ╠═34b354f6-5fe1-11eb-343e-c9b01ea8ba69
# ╠═7f60dda2-6220-11eb-3719-ad2fb7e64b25
# ╠═cab79ff0-5fe1-11eb-35bd-a1126ad2e3d0
# ╠═2c56c5c0-5fe1-11eb-129b-87f2d28290f9
# ╠═cec51f1a-6233-11eb-084f-f7556abecc9e
# ╠═2d65597c-7a76-11eb-2a9a-7fbde60b116e
# ╠═a767800c-7a75-11eb-04ab-952c9b518603
# ╠═dd7e92e4-5fda-11eb-35b6-81fcd9835ef1
# ╠═bddaf4a0-7922-11eb-04ef-3d30fe98b2be
# ╠═45e94934-5fde-11eb-39d9-67651b4de454
# ╠═e3887d1c-5fe4-11eb-1dbe-df46add45491
# ╠═414387d4-6239-11eb-114c-7136a6eb0277
# ╠═b512dd28-5fe5-11eb-386a-530180aa7448
# ╠═cda2cbd2-8e14-11eb-29e3-45aa278aaf60
# ╠═9c92bc0b-42de-42e2-aa4e-4bc9ba4e61b4
# ╟─00000000-0000-0000-0000-000000000001
# ╟─00000000-0000-0000-0000-000000000002
