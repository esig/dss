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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

import java.util.List;
import java.util.Objects;

/**
 * Builds JWS Compact Signature
 */
public class JAdESCompactBuilder extends AbstractJAdESBuilder {

	/**
	 * The default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 * @param parameters {@link JAdESSignatureParameters}
	 * @param documentsToSign a list of {@link DSSDocument}s to sign
	 */
	public JAdESCompactBuilder(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters, 
			final List<DSSDocument> documentsToSign) {
		super(certificateVerifier, parameters, documentsToSign);
	}

	/**
	 * Builds the concatenation of signed header and payload (dataTobeSigned string)
	 * in the way : BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS
	 * Payload)
	 * 
	 * @return {@link DSSDocument} representing the concatenated signature
	 */
	@Override
	public DSSDocument build(SignatureValue signatureValue) {
		assertConfigurationValidity(parameters);
		
		JWS jws = new JWS();
		incorporateHeader(jws);
		if (!SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
			incorporatePayload(jws);
		}
		String payload = parameters.isBase64UrlEncodedPayload() ? jws.getEncodedPayload() : jws.getUnverifiedPayload();
		byte[] signatureValueBytes = DSSASN1Utils.ensurePlainSignatureValue(parameters.getEncryptionAlgorithm(), signatureValue.getValue());
		
		String signatureString = DSSJsonUtils.concatenate(jws.getEncodedHeader(), payload, DSSJsonUtils.toBase64Url(signatureValueBytes));
		return new InMemoryDocument(signatureString.getBytes());
	}

	@Override
	public MimeType getMimeType() {
		return MimeType.JOSE;
	}

	@Override
	protected void assertConfigurationValidity(JAdESSignatureParameters signatureParameters) {
		Objects.requireNonNull(signatureParameters.getSignaturePackaging(), "SignaturePackaging shall be defined!");
		Objects.requireNonNull(signatureParameters.getSignatureLevel(), "SignatureLevel shall be defined!");

		SignaturePackaging packaging = signatureParameters.getSignaturePackaging();
		if (!(SignaturePackaging.ENVELOPING.equals(packaging)) && !(SignaturePackaging.DETACHED.equals(packaging))) {
			throw new IllegalArgumentException("Unsupported signature packaging for JAdES Compact Signature: " + packaging);
		}
		SignatureLevel signatureLevel = signatureParameters.getSignatureLevel();
		if (!SignatureLevel.JAdES_BASELINE_B.equals(signatureLevel)) {
			throw new IllegalArgumentException("Only JAdES_BASELINE_B level is allowed for JAdES Compact Signature! "
					+ "Change JwsSerializationType in JAdESSignatureParameters in order to support extension!");
		}
	}

}
