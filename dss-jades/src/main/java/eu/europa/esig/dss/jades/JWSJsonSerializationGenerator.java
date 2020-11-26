package eu.europa.esig.dss.jades;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

public class JWSJsonSerializationGenerator {

	private static final Logger LOG = LoggerFactory.getLogger(JWSJsonSerializationGenerator.class);

	private final JWSJsonSerializationObject jwsJsonSerializationObject;
	private final JWSSerializationType output;

	public JWSJsonSerializationGenerator(JWSJsonSerializationObject jwsJsonSerializationObject, JWSSerializationType output) {
		this.jwsJsonSerializationObject = jwsJsonSerializationObject;
		this.output = output;
	}

	public DSSDocument generate() {
		JsonObject jsonSerialization;
		switch (output) {
		case JSON_SERIALIZATION:
			jsonSerialization = buildJWSJsonSerialization();
			break;
		case FLATTENED_JSON_SERIALIZATION:
			jsonSerialization = buildFlattenedJwsJsonSerialization();
			break;
		default:
			throw new DSSException(String.format("The JWSJsonSerializationGenerator does not support the given JWS Serialization Type '%s'", output));
		}

		byte[] binaries = jsonSerialization.toJSONString().getBytes(StandardCharsets.UTF_8);
		return new InMemoryDocument(binaries);
	}

	private JsonObject buildJWSJsonSerialization() {
		if (JWSSerializationType.FLATTENED_JSON_SERIALIZATION.equals(jwsJsonSerializationObject.getJWSSerializationType())) {
			LOG.warn("A flattened signature will be transformed to a Complete JWS JSON Serialization Format!");
		}

		Map<String, Object> jsonSerializationMap = new LinkedHashMap<>();

		String payload = jwsJsonSerializationObject.getPayload();
		if (Utils.isStringNotBlank(payload)) {
			jsonSerializationMap.put(JWSConstants.PAYLOAD, payload);
		}

		List<JsonObject> signatureList = new ArrayList<>();
		for (JWS signature : jwsJsonSerializationObject.getSignatures()) {
			Map<String, Object> signatureMap = getSignatureJsonMap(signature);
			signatureList.add(new JsonObject(signatureMap));
		}
		jsonSerializationMap.put(JWSConstants.SIGNATURES, new JSONArray(signatureList));

		return new JsonObject(jsonSerializationMap);
	}

	private JsonObject buildFlattenedJwsJsonSerialization() {
		Map<String, Object> flattenedJwsMap = new LinkedHashMap<>();
		String payload = jwsJsonSerializationObject.getPayload();
		if (Utils.isStringNotBlank(payload)) {
			flattenedJwsMap.put(JWSConstants.PAYLOAD, payload);
		}

		List<JWS> signatures = jwsJsonSerializationObject.getSignatures();
		if (Utils.collectionSize(signatures) != 1) {
			throw new DSSException("JSON Flattened Serialization can only contain 1 signature (current : " + Utils.collectionSize(signatures) + ")");
		}

		JWS jws = signatures.iterator().next();
		Map<String, Object> signatureJsonMap = getSignatureJsonMap(jws);
		flattenedJwsMap.putAll(signatureJsonMap);

		return new JsonObject(flattenedJwsMap);
	}

	private Map<String, Object> getSignatureJsonMap(JWS signature) {
		Map<String, Object> signatureMap = new LinkedHashMap<>();

		String encodedProtected = signature.getEncodedHeader();
		if (Utils.isStringNotBlank(encodedProtected)) {
			signatureMap.put(JWSConstants.PROTECTED, encodedProtected);
		}

		Map<String, Object> unprotected = signature.getUnprotected();
		if (Utils.isMapNotEmpty(unprotected)) {
			signatureMap.put(JWSConstants.HEADER, unprotected);
		}

		String encodedSignatureValue = signature.getEncodedSignature();
		signatureMap.put(JWSConstants.SIGNATURE, encodedSignatureValue);

		return signatureMap;
	}

}
