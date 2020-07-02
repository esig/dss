package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;

public final class JWSConverter {

	private JWSConverter() {
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

		JWSJsonSerializationObject jwsJsonSerializationObject = new JWSJsonSerializationObject();
		jwsJsonSerializationObject.getSignatures().add(jws);
		jwsJsonSerializationObject.setFlattened(true);
		jwsJsonSerializationObject.setPayload(jws.getSignedPayload());

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject,
				JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

		return new InMemoryDocument(generator.generate(), "json-flattened-serialization.json", MimeType.JSON);
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

		JWSJsonSerializationObject jwsJsonSerializationObject = new JWSJsonSerializationObject();
		jwsJsonSerializationObject.getSignatures().add(jws);
		jwsJsonSerializationObject.setPayload(jws.getSignedPayload());

		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject, JWSSerializationType.JSON_SERIALIZATION);

		return new InMemoryDocument(generator.generate(), "json-serialization.json", MimeType.JSON);
	}

}
