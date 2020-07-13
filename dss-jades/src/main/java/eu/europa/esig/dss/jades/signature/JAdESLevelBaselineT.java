package eu.europa.esig.dss.jades.signature;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class JAdESLevelBaselineT implements SignatureExtension<JAdESSignatureParameters> {

	protected final CertificateVerifier certificateVerifier;

	/*
	 * The object encapsulating the Time Stamp Protocol needed to create the level
	 * -T, of the signature
	 */
	protected TSPSource tspSource;

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
	public DSSDocument extendSignatures(DSSDocument document, JAdESSignatureParameters params) throws DSSException {
		Objects.requireNonNull(document, "The document cannot be null");
		Objects.requireNonNull(tspSource, "The TSPSource cannot be null");

		JWSJsonSerializationParser parser = new JWSJsonSerializationParser(document);
		JWSJsonSerializationObject jwsJsonSerializationObject = parser.parse();

		if (jwsJsonSerializationObject == null || Utils.isCollectionEmpty(jwsJsonSerializationObject.getSignatures())) {
			throw new DSSException("There is no signature to extend!");
		}

		for (JWS signature : jwsJsonSerializationObject.getSignatures()) {

			JAdESSignature jadesSignature = new JAdESSignature(signature);
			jadesSignature.setDetachedContents(params.getDetachedContents());
			jadesSignature.prepareOfflineCertificateVerifier(certificateVerifier);

			extendSignature(jadesSignature, params);
		}

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				params.getJwsSerializationType());
		return new InMemoryDocument(generator.generate());
	}

	@SuppressWarnings("unchecked")
	protected void extendSignature(JAdESSignature jadesSignature, JAdESSignatureParameters params) {

		assertExtendSignatureToTPossible(jadesSignature, params);

		// The timestamp must be added only if there is no one or the extension -T level is being created
		if (!jadesSignature.hasTProfile() || SignatureLevel.JAdES_BASELINE_T.equals(params.getSignatureLevel())) {
			
			List<Object> unsignedProperties = getUnsignedProperties(jadesSignature);

			JAdESTimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
			DigestAlgorithm digestAlgorithmForTimestampRequest = signatureTimestampParameters.getDigestAlgorithm();
			byte[] digest = DSSUtils.digest(digestAlgorithmForTimestampRequest, jadesSignature.getSignatureValue());
			TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithmForTimestampRequest, digest);
			
			JsonObject tstContainer = JAdESUtils.getTstContainer(Collections.singletonList(timeStampResponse), null);
	
			JSONObject sigTstItem = new JSONObject();
			sigTstItem.put(JAdESHeaderParameterNames.SIG_TST, tstContainer);
			unsignedProperties.add(sigTstItem);
			
		}
	}

	@SuppressWarnings("unchecked")
	protected List<Object> getUnsignedProperties(JAdESSignature jadesSignature) {
		JWS jws = jadesSignature.getJws();
		Map<String, Object> unprotected = jws.getUnprotected();
		if (unprotected == null) {
			unprotected = new HashMap<>();
			jws.setUnprotected(unprotected);
		}

		return (List<Object>) unprotected.computeIfAbsent(JAdESHeaderParameterNames.ETSI_U, k -> new JSONArray());
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
