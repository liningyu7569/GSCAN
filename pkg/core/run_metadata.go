package core

type RunMetadata struct {
	Command      string
	Targets      []string
	Ports        []int
	Profiles     []string
	ServiceScan  bool
	OutputFile   string
	OutputFormat string
}

var currentRunMetadata RunMetadata

func SetRunMetadata(metadata RunMetadata) {
	currentRunMetadata = metadata
}

func GetRunMetadata() RunMetadata {
	metadata := currentRunMetadata
	metadata.Targets = append([]string(nil), metadata.Targets...)
	metadata.Ports = append([]int(nil), metadata.Ports...)
	metadata.Profiles = append([]string(nil), metadata.Profiles...)
	return metadata
}
