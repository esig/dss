/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_BASELINE_LT;

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

		final List<AdvancedSignature> signaturesToExtend = getExtendToLTLevelSignatures(signatures);
		if (Utils.isCollectionEmpty(signaturesToExtend)) {
			return;
		}

		// Reset sources
		for (AdvancedSignature signature : signaturesToExtend) {
			initializeSignatureBuilder((XAdESSignature) signature);

			// Data sources can already be loaded in memory (force reload)
			xadesSignature.resetCertificateSource();
			xadesSignature.resetRevocationSources();
			xadesSignature.resetTimestampSource();
		}

		final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker();
		if (XAdES_BASELINE_LT.equals(params.getSignatureLevel())) {
			signatureRequirementsChecker.assertExtendToLTLevelPossible(signaturesToExtend);
		}

		signatureRequirementsChecker.assertSignaturesValid(signaturesToExtend);
		signatureRequirementsChecker.assertCertificateChainValidForLTLevel(signaturesToExtend);

		// Perform signature validation
		ValidationDataContainer validationDataContainer = documentAnalyzer.getValidationData(signaturesToExtend);

		// Append ValidationData
		for (AdvancedSignature signature : signaturesToExtend) {
			initializeSignatureBuilder((XAdESSignature) signature);
			if (signatureRequirementsChecker.hasLTALevelOrHigher(signature)) {
				// avoid overriding of elements, when covered by an ArchiveTimeStamp
				continue;
			}

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

	private List<AdvancedSignature> getExtendToLTLevelSignatures(List<AdvancedSignature> signatures) {
		final List<AdvancedSignature> toBeExtended = new ArrayList<>();
		for (AdvancedSignature signature : signatures) {
			if (ltLevelExtensionRequired(signature)) {
				toBeExtended.add(signature);
			}
		}
		return toBeExtended;
	}

	private boolean ltLevelExtensionRequired(AdvancedSignature signature) {
		return XAdES_BASELINE_LT.equals(params.getSignatureLevel()) || !signature.hasLTAProfile();
	}

}
