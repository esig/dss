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

import org.apache.xml.security.Init;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.SignatureBuilder;
import eu.europa.esig.dss.xades.SignatureProfile;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

/**
 * Contains B level baseline profile for XAdES signature.
 *
 *
 */
public class XAdESLevelBaselineB implements SignatureProfile {

	static {

		Init.init();
	}

	/**
	 * the reference to the {@code CertificateVerifier} which provides information on the sources to be used in the validation process in the context of a signature.
	 */
	private CertificateVerifier certificateVerifier;

	/**
	 * The default constructor for XAdESLevelBaselineB.
	 *
	 * @param certificateVerifier
	 */
	public XAdESLevelBaselineB(final CertificateVerifier certificateVerifier) {

		this.certificateVerifier = certificateVerifier;
	}

	/**
	 * Returns the canonicalized <ds:SignedInfo> XML segment under the form of InputStream
	 *
	 * @param dssDocument The original dssDocument to sign.
	 * @param parameters  set of the driving signing parameters
	 * @return bytes
	 */
	public byte[] getDataToSign(final DSSDocument dssDocument, final XAdESSignatureParameters parameters) throws DSSException {
		final XAdESSignatureBuilder signatureBuilder = XAdESSignatureBuilder.getSignatureBuilder(parameters, dssDocument, certificateVerifier);
		parameters.getContext().setBuilder(signatureBuilder);
		final byte[] dataToSign = signatureBuilder.build();
		return dataToSign;
	}

	/**
	 * Adds the signature value to the signature.
	 *
	 * @param document       the original document to sign.
	 * @param parameters     set of the driving signing parameters
	 * @param signatureValue array of bytes representing the signature value.
	 * @return
	 * @throws DSSException
	 */
	@Override
	public DSSDocument signDocument(final DSSDocument document, final XAdESSignatureParameters parameters, final byte[] signatureValue) throws DSSException {
		SignatureBuilder builder = parameters.getContext().getBuilder();
		if (builder != null) {
			builder = parameters.getContext().getBuilder();
		} else {
			builder = XAdESSignatureBuilder.getSignatureBuilder(parameters, document, certificateVerifier);
		}
		final DSSDocument dssDocument = builder.signDocument(signatureValue);
		parameters.getContext().setBuilder(builder);
		return dssDocument;
	}
}
