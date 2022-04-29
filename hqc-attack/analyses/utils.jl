### A Pluto.jl notebook ###
# v0.12.21

using Markdown
using InteractiveUtils

# ╔═╡ 5f08d45e-7b39-11eb-1f9a-01d21e9003ad
struct AlignRight{T}
	s :: T
end

# ╔═╡ cabe8058-7b3a-11eb-244f-a1f8135d74f3
begin
	import Base: string
	string(x::AlignRight{T}) where {T} = string(x.s)
end

# ╔═╡ 28868ef0-7b39-11eb-2c2d-73305f92d401
aligned(elem::AlignRight{T}, padding) where {T} = padding * string(elem.s)

# ╔═╡ 6a63c858-7b3a-11eb-08e8-f7baf7535528
aligned(elem, padding) = string(elem) * padding

# ╔═╡ dfea9870-7b37-11eb-28b6-b5d07baffaba
function tablify(df)
	maxlengths = zeros(Int64, length(names(df)))
	for row in eachrow(df)
		for (i, x) in enumerate(row)
			maxlengths[i] = max(maxlengths[i], length(string(x)))
		end
	end
	for row in eachrow(df)
		for (i, x) in enumerate(row)
			padding = repeat(' ', maxlengths[i] - length(string(x)))
			ending = if i == length(maxlengths)
				" \\\\"
			else
				" & "
			end
			print(aligned(
				x,
					padding
			) * ending)
		end
		println()
	end
end

# ╔═╡ 772d2482-7b38-11eb-3cf5-4b65610baafb
percentify(prob) = AlignRight("\$\\approx $(convert(Float64, round(prob * 100, digits=1)))\\%\$")

# ╔═╡ Cell order:
# ╠═dfea9870-7b37-11eb-28b6-b5d07baffaba
# ╠═5f08d45e-7b39-11eb-1f9a-01d21e9003ad
# ╠═cabe8058-7b3a-11eb-244f-a1f8135d74f3
# ╠═28868ef0-7b39-11eb-2c2d-73305f92d401
# ╠═6a63c858-7b3a-11eb-08e8-f7baf7535528
# ╠═772d2482-7b38-11eb-3cf5-4b65610baafb
