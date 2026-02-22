package sdk

func includesName(include []string, name string) bool {
	if len(include) == 0 {
		return true
	}
	for _, candidate := range include {
		if candidate == name {
			return true
		}
	}
	return false
}

func excludesName(exclude []string, name string) bool {
	for _, candidate := range exclude {
		if candidate == name {
			return true
		}
	}
	return false
}
