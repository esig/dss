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

import org.w3c.dom.Element;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.ValidationContext;

/**
 * LT profile of XAdES signature
 *
 */
public class XAdESLevelBaselineLT extends XAdESLevelBaselineT {

	/**
	 * The default constructor for XAdESLevelBaselineLT.
	 */
	public XAdESLevelBaselineLT(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Adds CertificateValues and RevocationValues segments to UnsignedSignatureProperties.<br>
	 * An XML electronic signature MAY contain at most one:<br>
	 * - CertificateValues element and<br>
	 * - RevocationValues element.
	 *
	 * @see XAdESLevelX#extendSignatureTag()
	 */
	@Override
	protected void extendSignatureTag() throws DSSException {

		assertExtendSignatureToLTPossible();
		super.extendSignatureTag();
		Element levelTUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

		if (xadesSignature.hasLTAProfile()) {
			return;
		}

		// Timestamps can already be loaded in memory (force reload)
		xadesSignature.resetTimestampSource();

		/**
		 * In all cases the -LT level need to be regenerated.
		 */
		checkSignatureIntegrity();

		final ValidationContext validationContext = xadesSignature.getSignatureValidationContext(certificateVerifier);

		String indent = removeOldCertificateValues();
		removeOldRevocationValues();

		incorporateCertificateValues(unsignedSignaturePropertiesDom, validationContext, indent);
		incorporateRevocationValues(unsignedSignaturePropertiesDom, validationContext, indent);

		/**
		 * Certificate(s), revocation data where added, XAdES signature certificate source must be reset.
		 */
		xadesSignature.resetCertificateSource();
		xadesSignature.resetRevocationSources();
		
		unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelTUnsignedProperties);
	}

	/**
	 * This method checks the signature integrity and throws a {@code DSSException} if the signature is broken.
	 *
	 * @throws eu.europa.esig.dss.model.DSSException
	 */
	protected void checkSignatureIntegrity() throws DSSException {
		final SignatureCryptographicVerification signatureCryptographicVerification = xadesSignature.getSignatureCryptographicVerification();
		if (!signatureCryptographicVerification.isSignatureIntact()) {
			final String errorMessage = signatureCryptographicVerification.getErrorMessage();
			throw new DSSException("Cryptographic signature verification has failed" + (errorMessage.isEmpty() ? "." : (" / " + errorMessage)));
		}
	}

	/**
	 * This method removes old certificates values from the unsigned signature properties element.
	 */
	private String removeOldCertificateValues() {
		String text = null;
		final Element toRemove = xadesSignature.getCertificateValues();
		if (toRemove != null) {
			text = removeChild(unsignedSignaturePropertiesDom, toRemove);
			xadesSignature.resetCertificateSource();
		}
		return text;
	}

	/**
	 * This method removes old revocation values from the unsigned signature properties element.
	 */
	private void removeOldRevocationValues() {
		final Element toRemove = xadesSignature.getRevocationValues();
		if (toRemove != null) {
			removeChild(unsignedSignaturePropertiesDom, toRemove);
			xadesSignature.resetRevocationSources();
		}
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToLTPossible() {
		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if (SignatureLevel.XAdES_BASELINE_LT.equals(signatureLevel) && xadesSignature.hasLTAProfile()) {
			final String exceptionMessage = "Cannot extend signature. The signedData is already extended with [%s].";
			throw new DSSException(String.format(exceptionMessage, "XAdES LTA"));
		}
	}

}
