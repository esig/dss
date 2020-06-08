package eu.europa.esig.dss.jades.signature;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class JAdESCompactBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESCompactBuilder.class);
	
	private final JAdESSignatureParameters parameters;
	private final JAdESLevelBaselineB jadesLevelBaselineB;
	
	public JAdESCompactBuilder(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters, 
			final List<DSSDocument> documentsToSign) {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier must be defined!");
		Objects.requireNonNull(parameters, "SignatureParameters must be defined!");
		if (Utils.isCollectionEmpty(documentsToSign)) {
			throw new DSSException("Documents to sign must be provided!");
		}
		this.parameters = parameters;
		this.jadesLevelBaselineB = new JAdESLevelBaselineB(certificateVerifier, parameters, documentsToSign);
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
		if (!SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
			incorporatePayload(jws);
		}
		return JAdESUtils.concatenate(jws.getEncodedHeader(), jws.getEncodedPayload());
	}
	
	/**
	 * Builds data to be signed by incorporating a detached payload when required (see 5.2.8.3 Mechanism ObjectIdByURI)
	 * 
	 * @return {@link String} representing the signature data to be signed result
	 */
	public String buildDataToBeSigned() {
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
		if (payloadBytes != null) {
			if (LOG.isTraceEnabled()) {
				LOG.trace("The payload of created signature -> {}", new String(payloadBytes));
				LOG.trace("The base64 payload of created signature -> {}", Utils.toBase64(payloadBytes));
			}
			jws.setPayloadBytes(payloadBytes);
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
