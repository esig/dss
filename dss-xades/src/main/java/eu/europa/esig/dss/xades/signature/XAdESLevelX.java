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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.List;

import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_X;
import static eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_XL;

/**
 * This class represents the implementation of XAdES level -X extension.
 *
 */
public class XAdESLevelX extends XAdESLevelC {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESLevelX.class);

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

		for (AdvancedSignature signature : signatures) {
			initializeSignatureBuilder((XAdESSignature) signature);

			if (!xLevelExtensionRequired(params.getSignatureLevel())) {
				continue;
			}

			assertExtendSignatureToXPossible();

			removeOldTimestamps();

			final Element levelCUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

			final XAdESTimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
			final String canonicalizationMethod = signatureTimestampParameters.getCanonicalizationMethod();
			final byte[] timestampX1Data = xadesSignature.getTimestampSource().getTimestampX1Data(
					canonicalizationMethod, params.isEn319132());
			final DigestAlgorithm timestampDigestAlgorithm = signatureTimestampParameters.getDigestAlgorithm();
			final byte[] digestValue = DSSUtils.digest(timestampDigestAlgorithm, timestampX1Data);
			createXAdESTimeStampType(TimestampType.VALIDATION_DATA_TIMESTAMP, canonicalizationMethod, digestValue);
			
			unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelCUnsignedProperties);
		}
	}

	private boolean xLevelExtensionRequired(SignatureLevel signatureLevel) {
		return XAdES_X.equals(signatureLevel) || XAdES_XL.equals(signatureLevel) || !xadesSignature.hasXProfile();
	}

	private void removeOldTimestamps() {
		final NodeList sigAndRefsTimeStampList = xadesSignature.getSigAndRefsTimeStamp();
		if (sigAndRefsTimeStampList != null && sigAndRefsTimeStampList.getLength() > 0) {
			LOG.warn("An existing SigAndRefsTimeStamp found! " +
					"The entry will be removed in order to extend the signature with the updated data.");
		}
		removeNodes(sigAndRefsTimeStampList);

		NodeList refsOnlyTimestampTimeStamp = xadesSignature.getRefsOnlyTimestampTimeStamp();
		if (refsOnlyTimestampTimeStamp != null && refsOnlyTimestampTimeStamp.getLength() > 0) {
			LOG.warn("An existing RefsOnlyTimeStamp found! " +
					"The entry will be removed in order to extend the signature with the updated data.");
		}
		removeNodes(refsOnlyTimestampTimeStamp);
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToXPossible() {
		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if ((XAdES_X.equals(signatureLevel) && (xadesSignature.hasAProfile() ||
				(xadesSignature.hasXLProfile() && !xadesSignature.areAllSelfSignedCertificates()) )) ||
				(XAdES_XL.equals(signatureLevel) && xadesSignature.hasAProfile()) ) {
			throw new IllegalInputException(String.format(
					"Cannot extend signature to '%s'. The signature is already extended with higher level.", signatureLevel));
		}
	}

}
