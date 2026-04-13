package service

func optionalString(v string) *string {
	if v == "" {
		return nil
	}
	value := v
	return &value
}
