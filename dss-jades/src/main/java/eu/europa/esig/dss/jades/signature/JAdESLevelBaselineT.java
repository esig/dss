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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;

import java.util.Collections;
import java.util.Objects;

/**
 * Creates a T-level of a JAdES signature
 */
public class JAdESLevelBaselineT extends JAdESExtensionBuilder implements SignatureExtension<JAdESSignatureParameters> {

	/** The CertificateVerifier to use */
	protected final CertificateVerifier certificateVerifier;

	/**
	 * The object encapsulating the Time Stamp Protocol needed to create the level
	 * -T, of the signature
	 */
	protected TSPSource tspSource;

	/**
	 * The default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier} to use
	 */
	public JAdESLevelBaselineT(CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	/**
	 * Sets the TSP source to be used when extending the digital signature
	 *
	 * @param tspSource the tspSource to set
	 */
	public void setTspSource(final TSPSource tspSource) {
		this.tspSource = tspSource;
	}

	@Override
	public DSSDocument extendSignatures(DSSDocument document, JAdESSignatureParameters params) {
		Objects.requireNonNull(document, "The document cannot be null");
		Objects.requireNonNull(tspSource, "The TSPSource cannot be null");

		JWSJsonSerializationObject jwsJsonSerializationObject = toJWSJsonSerializationObjectToExtend(document);
		for (JWS signature : jwsJsonSerializationObject.getSignatures()) {
			assertEtsiUComponentsConsistent(signature, params.isBase64UrlEncodedEtsiUComponents());

			JAdESSignature jadesSignature = new JAdESSignature(signature);
			jadesSignature.setDetachedContents(params.getDetachedContents());
			jadesSignature.prepareOfflineCertificateVerifier(certificateVerifier);

			extendSignature(jadesSignature, params);
		}

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				params.getJwsSerializationType());
		return generator.generate();
	}

	/**
	 * Extends the signature
	 *
	 * @param jadesSignature {@link JAdESSignature} to be extended
	 * @param params {@link JAdESSignatureParameters} the extension parameters
	 */
	protected void extendSignature(JAdESSignature jadesSignature, JAdESSignatureParameters params) {

		assertExtendSignatureToTPossible(jadesSignature, params);

		// The timestamp must be added only if there is no one or the extension -T level is being created
		if (!jadesSignature.hasTProfile() || SignatureLevel.JAdES_BASELINE_T.equals(params.getSignatureLevel())) {

			JAdESTimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
			DigestAlgorithm digestAlgorithmForTimestampRequest = signatureTimestampParameters.getDigestAlgorithm();

			byte[] messageImprint = jadesSignature.getTimestampSource().getSignatureTimestampData();
			byte[] digest = DSSUtils.digest(digestAlgorithmForTimestampRequest, messageImprint);
			TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithmForTimestampRequest, digest);
			
			JsonObject tstContainer = DSSJsonUtils.getTstContainer(Collections.singletonList(timeStampResponse), null);

			JAdESEtsiUHeader etsiUHeader = jadesSignature.getEtsiUHeader();
			etsiUHeader.addComponent(jadesSignature.getJws(), JAdESHeaderParameterNames.SIG_TST, tstContainer,
					params.isBase64UrlEncodedEtsiUComponents());
		}
	}

	/**
	 * Checks if the extension is possible.
	 */
	private void assertExtendSignatureToTPossible(JAdESSignature jadesSignature, JAdESSignatureParameters params) {
		final SignatureLevel signatureLevel = params.getSignatureLevel();
		if (SignatureLevel.JAdES_BASELINE_T.equals(signatureLevel)
				&& (jadesSignature.hasLTProfile() || jadesSignature.hasLTAProfile())) {
			final String exceptionMessage = "Cannot extend signature. The signedData is already extended with [%s].";
			throw new DSSException(String.format(exceptionMessage, "JAdES LT"));
		}
	}

}
