package service

// optionalString 将空字符串转为nil指针，非空字符串转为指针
func optionalString(v string) *string {
	if v == "" {
		return nil
	}
	value := v
	return &value
}
