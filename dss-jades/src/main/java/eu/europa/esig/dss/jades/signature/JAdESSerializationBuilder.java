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

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

/**
 * Builds a JWS JSON Serialization signature
 *
 */
public class JAdESSerializationBuilder extends AbstractJAdESBuilder {

	/** The JWS signature container */
	private JWSJsonSerializationObject jwsJsonSerializationObject;

	/**
	 * The default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 * @param parameters {@link JAdESSignatureParameters}
	 * @param documentsToSign a list of {@link DSSDocument}s to sign
	 */
	public JAdESSerializationBuilder(final CertificateVerifier certificateVerifier,
			final JAdESSignatureParameters parameters,
			final List<DSSDocument> documentsToSign) {
		super(certificateVerifier, parameters, documentsToSign);
	}

	/**
	 * The constructor from an existing signature
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 * @param parameters {@link JAdESSignatureParameters}
	 * @param jwsJsonSerializationObject {@link JWSJsonSerializationObject} representing the existing signature(s)
	 */
	public JAdESSerializationBuilder(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters,
			final JWSJsonSerializationObject jwsJsonSerializationObject) {
		super(certificateVerifier, parameters, extractDocumentToBeSigned(parameters, jwsJsonSerializationObject));
		this.jwsJsonSerializationObject = jwsJsonSerializationObject;
	}

	private static List<DSSDocument> extractDocumentToBeSigned(JAdESSignatureParameters parameters, JWSJsonSerializationObject jwsJsonSerializationObject) {
		if (Utils.isStringNotBlank(jwsJsonSerializationObject.getPayload())) {
			// enveloping signature
			JWS jws = jwsJsonSerializationObject.getSignatures().get(0);

			byte[] payloadBytes;
			if (jws.isRfc7797UnencodedPayload()) {
				payloadBytes = jwsJsonSerializationObject.getPayload().getBytes(StandardCharsets.UTF_8);
			} else {
				payloadBytes = DSSJsonUtils.fromBase64Url(jwsJsonSerializationObject.getPayload());
			}
			return Collections.singletonList(new InMemoryDocument(payloadBytes));

		} else if (Utils.isCollectionNotEmpty(parameters.getDetachedContents())) {
			// detached signature
			return parameters.getDetachedContents();

		} else {
			throw new IllegalArgumentException("The payload or detached content must be provided!");
		}
	}

	@Override
	public DSSDocument build(SignatureValue signatureValue) {
		assertConfigurationValidity(parameters);

		JWS jws = getJWS();

		if (jwsJsonSerializationObject == null) {
			jwsJsonSerializationObject = new JWSJsonSerializationObject();
			if (!SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
				// do not include payload for detached case
				jwsJsonSerializationObject.setPayload(jws.getSignedPayload());
			}
		} else {
			assertB64ConfigurationConsistent();
		}

		byte[] signatureValueBytes = DSSASN1Utils.ensurePlainSignatureValue(parameters.getEncryptionAlgorithm(), signatureValue.getValue());
		jws.setSignature(signatureValueBytes);

		jwsJsonSerializationObject.getSignatures().add(jws);

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject, parameters.getJwsSerializationType());
		return generator.generate();
	}

	/**
	 * All not detached signatures must have the same 'b64' value
	 */
	private void assertB64ConfigurationConsistent() {
		// verify only for non-detached cases
		if (!SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
			boolean base64UrlEncodedPayload = parameters.isBase64UrlEncodedPayload();
			for (JWS jws : jwsJsonSerializationObject.getSignatures()) {
				if (base64UrlEncodedPayload != !jws.isRfc7797UnencodedPayload()) {
					throw new IllegalArgumentException("'b64' value shall be the same for all signatures! "
							+ "Change 'Base64UrlEncodedPayload' signature parameter or sign another file!");
				}
			}
		}
	}

	private JWS getJWS() {
		JWS jws = new JWS();
		incorporateHeader(jws);
		incorporatePayload(jws);
		return jws;
	}

	@Override
	public MimeType getMimeType() {
		return MimeTypeEnum.JOSE_JSON;
	}

	@Override
	protected void assertConfigurationValidity(JAdESSignatureParameters signatureParameters) {
		SignaturePackaging packaging = signatureParameters.getSignaturePackaging();
		if ((packaging != SignaturePackaging.ENVELOPING) && (packaging != SignaturePackaging.DETACHED)) {
			throw new IllegalArgumentException("Unsupported signature packaging for JSON Serialization Signature: " + packaging);
		}
		if (!JWSSerializationType.JSON_SERIALIZATION.equals(signatureParameters.getJwsSerializationType())
				&& jwsJsonSerializationObject != null) {
			throw new IllegalArgumentException(String.format("The '%s' type is not supported for a parallel signing!",
					signatureParameters.getJwsSerializationType()));
		}
	}

}
