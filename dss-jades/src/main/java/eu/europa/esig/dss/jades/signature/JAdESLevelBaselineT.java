package eu.europa.esig.dss.jades.signature;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jose4j.json.internal.json_simple.JSONObject;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
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

	private final CertificateVerifier certificateVerifier;

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
	private void extendSignature(JAdESSignature jadesSignature, JAdESSignatureParameters params) {

		assertExtendSignatureToTPossible(jadesSignature, params);

		JWS jws = jadesSignature.getJws();
		Map<String, Object> unprotected = jws.getUnprotected();
		if (unprotected == null) {
			unprotected = new HashMap<>();
			jws.setUnprotected(unprotected);
		}

		Map<String, Object> unsignedProperties = (Map<String, Object>) unprotected
				.get(JAdESHeaderParameterNames.ETSI_U);
		if (unsignedProperties == null) {
			unsignedProperties = new HashMap<>();
			unprotected.put(JAdESHeaderParameterNames.ETSI_U, unsignedProperties);
		}

		Map<String, Object> sigTst = (Map<String, Object>) unsignedProperties.get(JAdESHeaderParameterNames.SIG_TST);
		if (sigTst == null) {
			sigTst = new HashMap<>();
			unsignedProperties.put(JAdESHeaderParameterNames.SIG_TST, sigTst);
		}

		List<JSONObject> tsTokens = (List<JSONObject>) sigTst.get(JAdESHeaderParameterNames.TST_TOKENS);
		if (tsTokens == null) {
			tsTokens = new ArrayList<>();
			sigTst.put(JAdESHeaderParameterNames.TST_TOKENS, tsTokens);
		}

		JAdESTimestampParameters signatureTimestampParameters = params.getSignatureTimestampParameters();
		DigestAlgorithm digestAlgorithmForTimestampRequest = signatureTimestampParameters.getDigestAlgorithm();
		byte[] digest = DSSUtils.digest(digestAlgorithmForTimestampRequest, jadesSignature.getSignatureValue());
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithmForTimestampRequest, digest);

		JSONObject tst = new JSONObject();
		tst.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(timeStampResponse.getBytes()));

		tsTokens.add(tst);

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
