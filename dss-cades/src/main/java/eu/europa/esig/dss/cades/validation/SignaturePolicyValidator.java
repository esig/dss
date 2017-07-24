package eu.europa.esig.dss.cades.validation;

import java.util.Map;

import eu.europa.esig.dss.x509.SignaturePolicy;

public interface SignaturePolicyValidator {
	public Map<String, String> validate();
	public SignaturePolicy getSignaturePolicy();
}