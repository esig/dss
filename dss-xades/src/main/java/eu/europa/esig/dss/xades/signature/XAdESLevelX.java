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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.List;

import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_X;

/**
 * This class represents the implementation of XAdES level -X extension.
 *
 */
public class XAdESLevelX extends XAdESLevelC {

	/**
	 * The default constructor for XAdESLevelX.
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public XAdESLevelX(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Adds SigAndRefsTimeStamp segment to UnsignedSignatureProperties<br>
	 * The time-stamp is placed on the digital signature (ds:Signature element), the time-stamp(s) present in the
	 * XAdES-T form, the certification path references and the revocation status references.
	 *
	 * A XAdES-X form MAY contain several SigAndRefsTimeStamp elements, obtained from different TSAs.
	 *
	 * @see XAdESLevelC#extendSignatures(List)
	 */
	@Override
	protected void extendSignatures(List<AdvancedSignature> signatures) {
		super.extendSignatures(signatures);

		final List<AdvancedSignature> signaturesToExtend = getExtendToXLevelSignatures(signatures);
		if (Utils.isCollectionEmpty(signaturesToExtend)) {
			return;
		}

		final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker();
		if (XAdES_X.equals(params.getSignatureLevel())) {
			signatureRequirementsChecker.assertExtendToXLevelPossible(signaturesToExtend);
		}
		signatureRequirementsChecker.assertSignaturesValid(signaturesToExtend);

		for (AdvancedSignature signature : signaturesToExtend) {
			initializeSignatureBuilder((XAdESSignature) signature);
			if (!xLevelExtensionRequired(signature)) {
				// Unable to extend due to higher levels covering the current X-level
				continue;
			}

			final Element levelCUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

			final XAdESTimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
			final DigestAlgorithm digestAlgorithm = signatureTimestampParameters.getDigestAlgorithm();
			final String canonicalizationMethod = signatureTimestampParameters.getCanonicalizationMethod();
			final DSSMessageDigest messageDigest = xadesSignature.getTimestampSource().getTimestampX1MessageDigest(
					digestAlgorithm, canonicalizationMethod, params.isEn319132());
			createXAdESTimeStampType(TimestampType.VALIDATION_DATA_TIMESTAMP, canonicalizationMethod, messageDigest);
			
			unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelCUnsignedProperties);
		}
	}


	private List<AdvancedSignature> getExtendToXLevelSignatures(List<AdvancedSignature> signatures) {
		final List<AdvancedSignature> signaturesToExtend = new ArrayList<>();
		for (AdvancedSignature signature : signatures) {
			if (xLevelExtensionRequired(signature)) {
				signaturesToExtend.add(signature);
			}
		}
		return signaturesToExtend;
	}

	private boolean xLevelExtensionRequired(AdvancedSignature signature) {
		return XAdES_X.equals(params.getSignatureLevel()) || !signature.hasXProfile();
	}

}
