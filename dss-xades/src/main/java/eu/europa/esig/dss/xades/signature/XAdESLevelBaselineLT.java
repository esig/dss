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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;
import org.w3c.dom.Element;

import java.util.List;
import java.util.Set;

/**
 * LT profile of XAdES signature
 *
 */
public class XAdESLevelBaselineLT extends XAdESLevelBaselineT {

	/**
	 * The default constructor for XAdESLevelBaselineLT.
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
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
		
		super.extendSignatureTag();
		
		if (xadesSignature.hasLTAProfile()) {
			return;
		}

		// Data sources can already be loaded in memory (force reload)
		xadesSignature.resetCertificateSource();
		xadesSignature.resetRevocationSources();
		xadesSignature.resetTimestampSource();

		assertExtendSignatureToLTPossible();
		Element levelTUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

		/**
		 * In all cases the -LT level need to be regenerated.
		 */
		checkSignatureIntegrity();

		// must be executed before data removing
		final ValidationContext validationContext = xadesSignature.getSignatureValidationContext(certificateVerifier);

		String indent = removeOldCertificateValues();
		removeOldRevocationValues();
		
		ValidationDataForInclusion validationDataForInclusion = getValidationDataForInclusion(validationContext);

		Set<CertificateToken> certificateValuesToAdd = validationDataForInclusion.getCertificateTokens();
		List<CRLToken> crlsToAdd = validationDataForInclusion.getCrlTokens();
		List<OCSPToken> ocspsToAdd = validationDataForInclusion.getOcspTokens();
		
		incorporateCertificateValues(unsignedSignaturePropertiesDom, certificateValuesToAdd, indent);
		incorporateRevocationValues(unsignedSignaturePropertiesDom, crlsToAdd, ocspsToAdd, indent);
		
		unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelTUnsignedProperties);
	}

	/**
	 * This method checks the signature integrity and throws a {@code DSSException} if the signature is broken.
	 *
	 * @throws DSSException in case of the cryptographic signature verification fails
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
			/* Because the element was removed, the certificate source needs to be reset */
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
			/* Because the element was removed, the revocation sources need to be reset */
			xadesSignature.resetRevocationSources();
		}
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToLTPossible() {
		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if (SignatureLevel.XAdES_BASELINE_LT.equals(signatureLevel) && xadesSignature.hasLTAProfile()) {
			final String exceptionMessage = "Cannot extend the signature. The signedData is already extended with [%s]!";
			throw new DSSException(String.format(exceptionMessage, "XAdES LTA"));
		} else if (xadesSignature.areAllSelfSignedCertificates()) {
			throw new DSSException("Cannot extend the signature. The signature contains only self-signed certificate chains!");
		}
	}

}
