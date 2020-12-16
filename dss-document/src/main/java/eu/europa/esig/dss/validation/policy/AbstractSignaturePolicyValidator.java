/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.policy;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignaturePolicy;

public abstract class AbstractSignaturePolicyValidator implements SignaturePolicyValidator {

	private SignaturePolicy signaturePolicy;
	private boolean identified = false;
	private boolean status = false;
	private boolean asn1Processable = false;
	private boolean digestAlgorithmsEqual = false;
	private Map<String, String> errors = new HashMap<>();

	protected SignaturePolicy getSignaturePolicy() {
		return signaturePolicy;
	}

	@Override
	@Deprecated
	public void setSignature(AdvancedSignature signature) {
		this.signaturePolicy = signature.getSignaturePolicy();
	}
	
	@Override
	public void setSignaturePolicy(SignaturePolicy signaturePolicy) {
		this.signaturePolicy = signaturePolicy;
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
	
	@Override
	public Digest getComputedDigest(DigestAlgorithm digestAlgorithm) {
		// not implemented by default
		return null;
	}

}
