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
package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Crates a JWS Serialization signature
 */
public class JWSJsonSerializationGenerator {

	private static final Logger LOG = LoggerFactory.getLogger(JWSJsonSerializationGenerator.class);

	/** The container for JWS signature elements */
	private final JWSJsonSerializationObject jwsJsonSerializationObject;

	/** The target signature's format */
	private final JWSSerializationType output;

	/**
	 * Default constructor
	 *
	 * @param jwsJsonSerializationObject {@link JWSJsonSerializationObject} containing the signature data to create
	 * @param output {@link JWSSerializationType} the target output type
	 */
	public JWSJsonSerializationGenerator(JWSJsonSerializationObject jwsJsonSerializationObject, JWSSerializationType output) {
		this.jwsJsonSerializationObject = jwsJsonSerializationObject;
		this.output = output;
	}

	/**
	 * Generates the {@code DSSDocument}
	 *
	 * @return {@link DSSDocument} JWS signature
	 */
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
			throw new UnsupportedOperationException(String.format("The JWSJsonSerializationGenerator does not support the given JWS Serialization Type '%s'", output));
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
