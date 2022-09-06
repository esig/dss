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
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Contains utils for a JAdES signature format conversion
 */
public final class JWSConverter {

	/** The name for a Flattened Serialization signature */
	private static final String FLATTENED_SERIALIZATION_DOCUMENT_NAME = "json-flattened-serialization.json";

	/** The name for a JSON Serialization signature */
	private static final String SERIALIZATION_DOCUMENT_NAME = "json-serialization.json";

	/** The name for a signature containing JSON components in clear JSON form */
	private static final String CLEAR_ETSIU_DOCUMENT_NAME = "etsiU-clear-incorporation.json";

	/** The name for a signature containing JSON components in their corresponding base64url encoded form */
	private static final String BASE64URL_ETSIU_DOCUMENT_NAME = "etsiU-base64url-incorporation.json";

	private static List<String> timestampHeaderNames;

	static {
		timestampHeaderNames = Arrays.asList(JAdESHeaderParameterNames.ARC_TST, JAdESHeaderParameterNames.RFS_TST,
				JAdESHeaderParameterNames.SIG_R_TST);
	}

	private JWSConverter() {
		// empty
	}

	/**
	 * Converts a JWS Compact Serialization to a JSON Flattened Serialization.
	 * 
	 * @param document original document with a JWS Compact Serialization signature
	 * @return the converted signature with JSON Flattened Serialization format
	 */
	public static DSSDocument fromJWSCompactToJSONFlattenedSerialization(DSSDocument document) {
		JWSCompactSerializationParser parser = new JWSCompactSerializationParser(document);
		JWS jws = parser.parse();

		JWSJsonSerializationObject jwsJsonSerializationObject = DSSJsonUtils.toJWSJsonSerializationObject(jws);
		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

		DSSDocument signatureDocument = generator.generate();
		signatureDocument.setName(FLATTENED_SERIALIZATION_DOCUMENT_NAME);
		signatureDocument.setMimeType(MimeTypeEnum.JSON);
		return signatureDocument;
	}

	/**
	 * Converts a JWS Compact Serialization to a JSON Serialization.
	 * 
	 * @param document original document with a JWS Compact Serialization signature
	 * @return the converted signature with JSON Serialization format
	 */
	public static DSSDocument fromJWSCompactToJSONSerialization(DSSDocument document) {
		JWSCompactSerializationParser parser = new JWSCompactSerializationParser(document);
		JWS jws = parser.parse();

		JWSJsonSerializationObject jwsJsonSerializationObject = DSSJsonUtils.toJWSJsonSerializationObject(jws);
		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				JWSSerializationType.JSON_SERIALIZATION);

		DSSDocument signatureDocument = generator.generate();
		signatureDocument.setName(SERIALIZATION_DOCUMENT_NAME);
		signatureDocument.setMimeType(MimeTypeEnum.JSON);
		return signatureDocument;
	}

	/**
	 * Converts unprotected content of 'etsiU' header of JAdES signatures inside a
	 * document to its clear JSON incorporation form
	 * 
	 * @param document {@link DSSDocument} containing Serialization (or Flattened)
	 *                 JAdES signatures
	 * @return {@link DSSDocument} containing signatures with 'etsiU' header in its
	 *         clear JSON representation
	 */
	public static DSSDocument fromEtsiUWithBase64UrlToClearJsonIncorporation(DSSDocument document) {
		JWSJsonSerializationParser parser = new JWSJsonSerializationParser(document);
		JWSJsonSerializationObject jwsJsonSerializationObject = parser.parse();

		for (JWS jws : jwsJsonSerializationObject.getSignatures()) {
			List<Object> etsiUContent = DSSJsonUtils.getEtsiU(jws);
			if (Utils.isCollectionEmpty(etsiUContent)) {
				// do nothing
				continue;
			}

			assertConvertPossible(etsiUContent);

			List<Object> clearEtsiUContent = toClearJsonIncorporation(etsiUContent);
			Map<String, Object> unprotected = jws.getUnprotected();
			unprotected.replace(JAdESHeaderParameterNames.ETSI_U, clearEtsiUContent);
		}

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				jwsJsonSerializationObject.getJWSSerializationType());

		DSSDocument signatureDocument = generator.generate();
		signatureDocument.setName(CLEAR_ETSIU_DOCUMENT_NAME);
		signatureDocument.setMimeType(MimeTypeEnum.JSON);
		return signatureDocument;
	}

	private static void assertConvertPossible(List<Object> etsiUContent) {
		if (!DSSJsonUtils.checkComponentsUnicity(etsiUContent)) {
			throw new DSSException("Unable to convert the EtsiU content! All components shall have a common form.");
		}
	}

	private static List<Object> toClearJsonIncorporation(List<Object> etsiUContent) {
		List<Object> clearEtsiUContent = new ArrayList<>();
		for (Object item : etsiUContent) {
			Map<String, Object> clearEtsiUComponent = DSSJsonUtils.parseEtsiUComponent(item);
			if (clearEtsiUComponent == null) {
				throw new DSSException(String.format("Unable to parse 'etsiU' component : '%s'", item));
			}
			assertComponentSupportsConversion(clearEtsiUComponent);
			clearEtsiUContent.add(new JsonObject(clearEtsiUComponent));
		}
		return clearEtsiUContent;
	}

	/**
	 * Converts unprotected content of 'etsiU' header of JAdES signatures inside a
	 * document to its base64Url JSON incorporation form
	 * 
	 * @param document {@link DSSDocument} containing Serialization (or Flattened)
	 *                 JAdES signatures
	 * @return {@link DSSDocument} containing signatures with 'etsiU' header in its
	 *         base64Url encoded representation
	 */
	public static DSSDocument fromEtsiUWithClearJsonToBase64UrlIncorporation(DSSDocument document) {
		JWSJsonSerializationParser parser = new JWSJsonSerializationParser(document);
		JWSJsonSerializationObject jwsJsonSerializationObject = parser.parse();

		for (JWS jws : jwsJsonSerializationObject.getSignatures()) {
			List<Object> etsiUContent = DSSJsonUtils.getEtsiU(jws);
			if (Utils.isCollectionEmpty(etsiUContent)) {
				// do nothing
				continue;
			}

			assertConvertPossible(etsiUContent);

			List<Object> base64UrlEtsiUContent = toBase64UrlIncorporation(etsiUContent);
			Map<String, Object> unprotected = jws.getUnprotected();
			unprotected.replace(JAdESHeaderParameterNames.ETSI_U, base64UrlEtsiUContent);
		}

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				jwsJsonSerializationObject.getJWSSerializationType());

		DSSDocument signatureDocument = generator.generate();
		signatureDocument.setName(BASE64URL_ETSIU_DOCUMENT_NAME);
		signatureDocument.setMimeType(MimeTypeEnum.JSON);
		return signatureDocument;
	}

	private static List<Object> toBase64UrlIncorporation(List<Object> etsiUContent) {
		List<Object> base64UrlEtsiUContent = new ArrayList<>();
		for (Object item : etsiUContent) {
			Map<String, Object> base64UrlEtsiUComponent = DSSJsonUtils.parseEtsiUComponent(item);
			if (base64UrlEtsiUComponent == null) {
				throw new DSSException(String.format("Unable to parse 'etsiU' component : '%s'", item));
			}
			assertComponentSupportsConversion(base64UrlEtsiUComponent);
			base64UrlEtsiUContent.add(DSSJsonUtils.toBase64Url(base64UrlEtsiUComponent));
		}
		return base64UrlEtsiUContent;
	}

	private static void assertComponentSupportsConversion(Map<String, Object> etsiUComponent) {
		// only one is allowed
		String componentName = etsiUComponent.keySet().iterator().next();
		if (timestampHeaderNames.contains(componentName)) {
			throw new DSSException(String.format("Unable to convert a signature! "
					+ "'etsiU' contains a component with name '%s', which is sensible to a format change.", componentName));
		}
	}

}
