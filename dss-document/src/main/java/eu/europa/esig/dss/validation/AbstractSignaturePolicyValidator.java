package eu.europa.esig.dss.validation;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import eu.europa.esig.dss.x509.SignaturePolicy;

public abstract class AbstractSignaturePolicyValidator implements SignaturePolicyValidator {

	private AdvancedSignature signature;
	private boolean identified = false;
	private boolean status = false;
	private boolean asn1Processable = false;
	private boolean digestAlgorithmsEqual = false;
	private Map<String, String> errors = new HashMap<String, String>();

	protected AdvancedSignature getSignature() {
		return signature;
	}

	protected SignaturePolicy getSignaturePolicy() {
		return signature.getPolicyId();
	}

	@Override
	public void setSignature(AdvancedSignature signature) {
		this.signature = signature;
	}

	protected void setIdentified(boolean identified) {
		this.identified = identified;
	}

	protected void setStatus(boolean status) {
		this.status = status;
	}

	protected void setAsn1Processable(boolean asn1Processable) {
		this.asn1Processable = asn1Processable;
	}

	protected void setDigestAlgorithmsEqual(boolean digestAlgorithmsEqual) {
		this.digestAlgorithmsEqual = digestAlgorithmsEqual;
	}

	@Override
	public boolean isIdentified() {
		return identified;
	}

	@Override
	public boolean isStatus() {
		return status;
	}

	@Override
	public boolean isAsn1Processable() {
		return asn1Processable;
	}

	@Override
	public boolean isDigestAlgorithmsEqual() {
		return digestAlgorithmsEqual;
	}

	protected void addError(String key, String description) {
		this.errors.put(key, description);
	}

	@Override
	public String getProcessingErrors() {
		StringBuilder stringBuilder = new StringBuilder();
		if (!errors.isEmpty()) {
			stringBuilder.append("The errors found on signature policy validation are:");
			for (Entry<String, String> entry : errors.entrySet()) {
				stringBuilder.append(" at ").append(entry.getKey()).append(": ").append(entry.getValue()).append(",");
			}
			stringBuilder.setLength(stringBuilder.length() - 1);
		}
		return stringBuilder.toString();
	}

}
