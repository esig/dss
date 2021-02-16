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

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Abstract JAdES signature builder
 */
public abstract class AbstractJAdESBuilder implements JAdESBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractJAdESBuilder.class);

	/** Signature parameters */
	protected final JAdESSignatureParameters parameters;

	/** The instance of a B-level generator class */
	protected final JAdESLevelBaselineB jadesLevelBaselineB;

	/**
	 * Default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier} to use
	 * @param parameters {@link JAdESSignatureParameters}
	 * @param documentsToSign a list of {@link DSSDocument}s to sign
	 */
	protected AbstractJAdESBuilder(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters, 
			final List<DSSDocument> documentsToSign) {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier must be defined!");
		Objects.requireNonNull(parameters, "SignatureParameters must be defined!");
		if (Utils.isCollectionEmpty(documentsToSign)) {
			throw new DSSException("Documents to sign must be provided!");
		}
		this.parameters = parameters;
		this.jadesLevelBaselineB = new JAdESLevelBaselineB(certificateVerifier, parameters, documentsToSign);
	}
	
	@Override
	public ToBeSigned buildDataToBeSigned() {
		assertConfigurationValidity(parameters);
		
		JWS jws = new JWS();
		incorporateHeader(jws);
		incorporatePayload(jws);
		
		byte[] dataToSign = DSSJsonUtils.getSigningInputBytes(jws);
		return new ToBeSigned(dataToSign);
	}
	
	/**
	 * Incorporates Signed Header
	 * 
	 * @param jws {@link JWS} to populate
	 */
	protected void incorporateHeader(final JWS jws) {
		Map<String, Object> signedProperties = jadesLevelBaselineB.getSignedProperties();
		for (Map.Entry<String, Object> signedHeader : signedProperties.entrySet()) {
			jws.setHeader(signedHeader.getKey(), signedHeader.getValue());
		}
	}

	/**
	 * Incorporates Payload
	 * 
	 * @param jws {@link JWS} to populate
	 */
	protected void incorporatePayload(final JWS jws) {
		byte[] payloadBytes = jadesLevelBaselineB.getPayloadBytes();
		if (Utils.isArrayNotEmpty(payloadBytes)) {
			if (LOG.isTraceEnabled()) {
				LOG.trace("The payload of created signature -> {}", new String(payloadBytes));
				LOG.trace("The base64 payload of created signature -> {}", Utils.toBase64(payloadBytes));
			}
			jws.setPayloadBytes(payloadBytes);
		}
	}

	/**
	 * Verifies if the given signaturePackaging type is supported
	 * Throws an Exception if the configuration is not valid
	 *
	 * @param signatureParameters {@link JAdESSignatureParameters}
	 */
	protected abstract void assertConfigurationValidity(final JAdESSignatureParameters signatureParameters);

}
