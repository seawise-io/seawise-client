package protocol

import "slices"

// TestVectorKeyIDs are the key IDs of every key in testdata/vectors. Their
// seeds are published, so a production server must refuse to register them
// and the agent refuses to use them.
var TestVectorKeyIDs = []string{
	"ZjaJZwcHBYrpGDKzt14xb29K8hbw4dWAkq90oCxfEYo", // device-a
	"s6XaxZBr2_jRf5lAfSp2AZGefGjRScK25ZnTrMfJhyE", // device-b
	"UdnxjHZEOlOgVnN35a_doDOwVLH-VkHgx9-4EoYHt_k", // device-c
	"kuBFTnLvMBhibU5Y94o0K7z9ZkNPeyhf_d551BGsXZM", // device-new
	"9P4HhrZghO06DZVBjUDR-DsB2YmNRh16oLik6sxNqFQ", // device-old
	"iH26UuvyaS6bfEgWBn1CQoDaNlhnBXDPVTvnsz_qg2g", // root-primary
	"r0u3q9YF3CPCBg4A5KlgY6nTPiD27I2r1gU6DIuYVWw", // root-backup
	"wl1K9dFf_OlEkxUs6UO2KJ_i8MmhO9gXSz_q9rqA04E", // root-rogue
	"rHx4_qo4C5VMhPcxeR61besR2g88ynYAZRtU4ETELQ0", // control-1
	"N-GeDx0GLx5zeOS6LwjiKr-xaGvH-MRf4Q2lmQ8VyzM", // control-2
	"_TtkVZP1U3y1gGI0sGoAspbzi_nY5diBoOhz1BgMsv8", // control-old
	"HRa_ACQ2QGeEbNwJwkJ_TFPzihYPKMjdNTSEVqDdhxY", // control-rogue
	"mxs4IdKuzGDnvt-UtyEenGBbbKEKqZol-3ImhEZxzxQ", // visitor-1
	"9JvEpdDSJQjZHGypEiPTFy1NCiNGHMTB7icqfxSiADI", // edge-1
	"Jk_11RdGyHmmwBtWX3qV3UOXqKGAzf8t7gGrVTJ0Tms", // release-1
}

// IsTestVectorKey reports whether kid belongs to a published test key.
func IsTestVectorKey(kid string) bool { return slices.Contains(TestVectorKeyIDs, kid) }
