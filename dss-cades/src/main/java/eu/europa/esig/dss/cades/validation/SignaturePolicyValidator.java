package eu.europa.esig.dss.cades.validation;

import java.util.Map;

import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.x509.SignaturePolicy;

public interface SignaturePolicyValidator<T extends AdvancedSignature> {
	public void setSignaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider);
	public void setSignature(T cadesSignature);
	
	public Map<String, String> validate();
	
	public SignaturePolicy getSignaturePolicy();
}