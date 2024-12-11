package nvgpu

import (
	"fmt"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/intel/trustauthority-client/go-connector"
)

type GPUEvidence struct {
	Arch          string                  `json:"arch"`
	Evidence      string                  `json:"evidence"`
	Certificate   string                  `json:"certificate"`
	Nonce         []byte                  `json:"gpu_nonce"`
	VerifierNonce connector.VerifierNonce `json:"verifier_nonce"`
}

type GPUAdapter struct {
}

func NewCompositeEvidenceAdapter() connector.CompositeEvidenceAdapter {
	return &GPUAdapter{}
}

func (adapter *GPUAdapter) GetEvidenceIdentifier() string {
	return "nvgpu"
}

func (adapter *GPUAdapter) CollectEvidence(nonce []byte) (GPUEvidence, error) {
	gpuAttester := gonvtrust.NewGpuAttester(true)
	evidenceList, err := gpuAttester.GetRemoteEvidence(123123)
	if err != nil {
		return GPUEvidence{}, fmt.Errorf("failed to get remote evidence: %v", err)
	}

	if len(evidenceList) == 0 {
		return GPUEvidence{}, fmt.Errorf("no evidence returned")
	}
	// only single gpu attestation is supported for now
	rawEvidence := evidenceList[0]

	return GPUEvidence{
		Nonce:       nonce,
		Arch:        "HOPPER",
		Evidence:    rawEvidence.Evidence,
		Certificate: rawEvidence.Certificate,
	}, nil

}

func (adapter *GPUAdapter) GetEvidence(verifierNonce *connector.VerifierNonce, userData []byte) (interface{}, error) {
	var nonce []byte
	if verifierNonce != nil {
		nonce = append(verifierNonce.Val, verifierNonce.Iat[:]...)
	}

	evidence, err := adapter.CollectEvidence(nonce)
	if err != nil {
		return nil, err
	}

	evidence.VerifierNonce = *verifierNonce

	return &evidence, nil

}
