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

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.TimestampParameters;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * This class represents the implementation of XAdES level -X extension.
 *
 *
 */

public class XAdESLevelX extends XAdESLevelC {

	/**
	 * The default constructor for XAdESLevelX.
	 */
	public XAdESLevelX(CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
	}

	/**
	 * Adds <SigAndRefsTimeStamp> segment to <UnsignedSignatureProperties><br>
	 * The time-stamp is placed on the the digital signature (ds:Signature element), the time-stamp(s) present in the
	 * XAdES-T form, the certification path references and the revocation status references.
	 *
	 * A XAdES-X form MAY contain several SigAndRefsTimeStamp elements, obtained from different TSAs.
	 *
	 * @see XAdESLevelC#extendSignatureTag()
	 */
	@Override
	protected void extendSignatureTag() throws DSSException {

		/* Go up to -C */
		super.extendSignatureTag();

		final SignatureLevel signatureLevel = params.getSignatureLevel();
		// for XAdES_XL the development is not conform with the standard
		if (!xadesSignature.hasXProfile() || SignatureLevel.XAdES_X.equals(signatureLevel) || SignatureLevel.XAdES_XL.equals(signatureLevel)) {

			if (SignatureLevel.XAdES_XL.equals(params.getSignatureLevel())) {

				final NodeList toRemoveList = xadesSignature.getSigAndRefsTimeStamp();
				for (int index = 0; index < toRemoveList.getLength(); index++) {

					final Node item = toRemoveList.item(index);
					unsignedSignaturePropertiesDom.removeChild(item);
				}
			}

			final TimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
			final String canonicalizationMethod = signatureTimestampParameters.getCanonicalizationMethod();
			final byte[] timestampX1Data = xadesSignature.getTimestampX1Data(null, canonicalizationMethod);
			final DigestAlgorithm timestampDigestAlgorithm = signatureTimestampParameters.getDigestAlgorithm();
			final byte[] digestValue = DSSUtils.digest(timestampDigestAlgorithm, timestampX1Data);
			createXAdESTimeStampType(TimestampType.VALIDATION_DATA_TIMESTAMP, canonicalizationMethod, digestValue);
		}
	}
}
