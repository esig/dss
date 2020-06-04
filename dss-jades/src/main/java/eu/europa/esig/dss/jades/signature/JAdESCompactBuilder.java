package eu.europa.esig.dss.jades.signature;

import java.util.Map;
import java.util.Objects;

import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class JAdESCompactBuilder {
	
	private final CertificateVerifier certificateVerifier;
	private final JAdESSignatureParameters parameters;
	private final DSSDocument signingDocument;
	
	public JAdESCompactBuilder(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters, 
			final DSSDocument signingDocument) {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier must be defined!");
		Objects.requireNonNull(parameters, "SignatureParameters must be defined!");
		this.certificateVerifier = certificateVerifier;
		this.parameters = parameters;
		this.signingDocument = signingDocument;
	}
	
	/**
	 * Builds the concatenation of signed header and payload (dataTobeSigned string) in the way :
	 * BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)
	 * 
	 * @return {@link String} representing the concatenation result
	 */
	public String build() {
		assertSignaturePackaging(parameters.getSignaturePackaging());
		
		JWS jws = new JWS();
		incorporateHeader(jws);
		incorporatePayload(jws);
		return JAdESUtils.concatenate(jws.getEncodedHeader(), jws.getEncodedPayload());
	}
	
	/**
	 * Incorporates Signed Header
	 * 
	 * @param jws {@link JWS} to populate
	 */
	protected void incorporateHeader(final JWS jws) {
		JAdESLevelBaselineB jadesLevelBaselineB = new JAdESLevelBaselineB(certificateVerifier, parameters, signingDocument);
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
		if (!SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
			jws.setPayloadBytes(DSSUtils.toByteArray(signingDocument));
		}
	}

	/**
	 * Verifies if the given signaturePackaging type is supported
	 * 
	 * @param packaging
	 *            {@code SignaturePackaging} to be checked
	 * @throws DSSException
	 *             if the packaging is not supported for this kind of signature
	 */
	protected void assertSignaturePackaging(final SignaturePackaging packaging) throws DSSException {
		if ((packaging != SignaturePackaging.ENVELOPING) && (packaging != SignaturePackaging.DETACHED)) {
			throw new DSSException("Unsupported signature packaging: " + packaging);
		}
	}

}
