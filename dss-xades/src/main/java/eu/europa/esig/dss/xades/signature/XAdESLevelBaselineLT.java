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
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationData;
import eu.europa.esig.dss.validation.ValidationDataContainer;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
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
	 * @see XAdESLevelBaselineT#extendSignatures(List)
	 */
	@Override
	protected void extendSignatures(List<AdvancedSignature> signatures) {
		super.extendSignatures(signatures);

		boolean ltLevelRequired = false;

		// Reset sources
		for (AdvancedSignature signature : signatures) {
			initializeSignatureBuilder((XAdESSignature) signature);
			if (xadesSignature.hasLTAProfile()) {
				continue;
			}

			/**
			 * In all cases the -LT level need to be regenerated.
			 */
			checkSignatureIntegrity();

			// Data sources can already be loaded in memory (force reload)
			xadesSignature.resetCertificateSource();
			xadesSignature.resetRevocationSources();
			xadesSignature.resetTimestampSource();

			ltLevelRequired = true;
		}

		if (!ltLevelRequired) {
			return;
		}

		// Perform signature validation
		ValidationDataContainer validationDataContainer = documentValidator.getValidationData(signatures);

		// Append ValidationData
		for (AdvancedSignature signature : signatures) {
			initializeSignatureBuilder((XAdESSignature) signature);
			if (xadesSignature.hasLTAProfile()) {
				continue;
			}

			// shall be called after source re-generation and validation data inclusion
			assertExtendSignatureToLTPossible();

			String indent = removeOldCertificateValues();
			removeOldRevocationValues();

			Element levelTUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

			ValidationData validationDataForInclusion = validationDataContainer.getCompleteValidationDataForSignature(signature);

			Set<CertificateToken> certificateValuesToAdd = validationDataForInclusion.getCertificateTokens();
			Set<CRLToken> crlsToAdd = validationDataForInclusion.getCrlTokens();
			Set<OCSPToken> ocspsToAdd = validationDataForInclusion.getOcspTokens();

			incorporateCertificateValues(unsignedSignaturePropertiesDom, certificateValuesToAdd, indent);
			incorporateRevocationValues(unsignedSignaturePropertiesDom, crlsToAdd, ocspsToAdd, indent);

			unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelTUnsignedProperties);
		}
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToLTPossible() {
		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if (SignatureLevel.XAdES_BASELINE_LT.equals(signatureLevel) && xadesSignature.hasLTAProfile()) {
			final String exceptionMessage = "Cannot extend the signature. The signature is already extended with [%s]!";
			throw new DSSException(String.format(exceptionMessage, "XAdES LTA"));
		} else if (xadesSignature.areAllSelfSignedCertificates()) {
			throw new DSSException("Cannot extend the signature. The signature contains only self-signed certificate chains!");
		}
	}

}
