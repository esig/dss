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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.xml.XMLCanonicalizer;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

import java.util.Objects;

/**
 * Parameters for a XAdES counter-signature creation
 */
public class XAdESCounterSignatureParameters extends XAdESSignatureParameters implements SerializableCounterSignatureParameters {
	
	private static final long serialVersionUID = -1443369404631708953L;

	/**
	 * Signature Id to be counter-signed
	 * 
	 * Can be a DSS Id or XMLDSIG Signature Id
	 */
	private String signatureIdToCounterSign;
	
	/**
	 * The canonicalization method used for a SignatureValue canonicalization
	 * The EXCLUSIVE canonicalization is used by default
	 */
	private String counterSignatureCanonicalizationMethod = XMLCanonicalizer.DEFAULT_DSS_C14N_METHOD;

	/**
	 * Default constructor instantiating object with null values
	 */
	public XAdESCounterSignatureParameters() {
		// empty
	}

	@Override
	public String getSignatureIdToCounterSign() {
		return signatureIdToCounterSign;
	}
	
	@Override
	public void setSignatureIdToCounterSign(String signatureId) {
		this.signatureIdToCounterSign = signatureId;
	}

	/**
	 * Returns a canonicalization method used for a counter-signed SignatureValue
	 * 
	 * @return {@link String} canonicalization method to use
	 */
	public String getCounterSignatureCanonicalizationMethod() {
		return counterSignatureCanonicalizationMethod;
	}

	/**
	 * Sets a canonicalization method used for a counter-signed SignatureValue
	 * 
	 * @param counterSignatureCanonicalizationMethod {@link String} canonicalization method to use
	 */
	public void setCounterSignatureCanonicalizationMethod(String counterSignatureCanonicalizationMethod) {
		this.counterSignatureCanonicalizationMethod = counterSignatureCanonicalizationMethod;
	}

	@Override
	public String getDeterministicId() {
		String deterministicId = getContext().getDeterministicId();
		if (deterministicId == null) {
			final TokenIdentifier identifier = (getSigningCertificate() == null ? null : getSigningCertificate().getDSSId());
			deterministicId = DSSUtils.getCounterSignatureDeterministicId(bLevel().getSigningDate(), identifier, signatureIdToCounterSign);
			getContext().setDeterministicId(deterministicId);
		}
		return deterministicId;
	}

	@Override
	public String toString() {
		return "XAdESCounterSignatureParameters{" +
				"signatureIdToCounterSign='" + signatureIdToCounterSign + '\'' +
				", counterSignatureCanonicalizationMethod='" + counterSignatureCanonicalizationMethod + '\'' +
				"} " + super.toString();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof XAdESCounterSignatureParameters)) return false;
		if (!super.equals(o)) return false;

		XAdESCounterSignatureParameters that = (XAdESCounterSignatureParameters) o;

		if (!Objects.equals(signatureIdToCounterSign, that.signatureIdToCounterSign))
			return false;
		return Objects.equals(counterSignatureCanonicalizationMethod, that.counterSignatureCanonicalizationMethod);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + (signatureIdToCounterSign != null ? signatureIdToCounterSign.hashCode() : 0);
		result = 31 * result + (counterSignatureCanonicalizationMethod != null ? counterSignatureCanonicalizationMethod.hashCode() : 0);
		return result;
	}

}
