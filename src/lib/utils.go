package wanted

func max(v ...int) int {
	res := v[0]
	for _, i := range v[1:] {
		if i > res {
			res = i
		}
	}
	return res
}
