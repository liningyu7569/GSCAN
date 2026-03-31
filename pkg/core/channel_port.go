package core

const (
	// BaseSourcePort keeps the multiplexed channel space in a valid user port range.
	BaseSourcePort uint16 = 4096
)

func encodeChannelPort(channelID uint16) uint16 {
	return BaseSourcePort + channelID
}

func decodeChannelPort(rawPort uint16) (uint16, bool) {
	if rawPort < BaseSourcePort {
		return 0, false
	}

	channelID := rawPort - BaseSourcePort
	if int(channelID) >= MaxCWNDLimit {
		return 0, false
	}

	return channelID, true
}
