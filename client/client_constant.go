package client

type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
	ClientTypeTrusted      ClientType = "trusted"
)
