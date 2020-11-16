package eu.europa.esig.dss.jades.signature;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public class JAdESCounterSignatureBuilder extends JAdESExtensionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESCounterSignatureBuilder.class);
	
	/**
	 * Extract SignatureValue binaries from the provided JAdES signature
	 * 
	 * @param signatureDocument {@link DSSDocument} to be counter-signed
	 * @param parameters {@link JAdESCounterSignatureParameters}
	 * @return {@link DSSDocument} extracted SignatureValue
	 */
	public DSSDocument getSignatureValueToBeSigned(DSSDocument signatureDocument, JAdESCounterSignatureParameters parameters) {
		JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(signatureDocument);
		JWSJsonSerializationObject jwsJsonSerializationObject = jwsJsonSerializationParser.parse();
		
		JAdESSignature jadesSignature = extractSignatureById(jwsJsonSerializationObject, parameters.getSignatureIdToCounterSign());
		return new InMemoryDocument(jadesSignature.getSignatureValue());
	}
	
	/**
	 * Embeds and returns the embedded counter signature into the original JAdES signature
	 * 
	 * @param signatureDocument {@link DSSDocument} the original document containing the signature to be counter signed
	 * @param counterSignature {@link DSSDocument} the counter signature
	 * @param parameters {@link JAdESCounterSignatureParameters}
	 * @return {@link DSSDocument} original signature enveloping the {@code counterSignature} in an unprotected header
	 */
	public DSSDocument buildEmbeddedCounterSignature(DSSDocument signatureDocument, DSSDocument counterSignature, 
			JAdESCounterSignatureParameters parameters) {
		JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(signatureDocument);
		JWSJsonSerializationObject jwsJsonSerializationObject = jwsJsonSerializationParser.parse();
		
		JAdESSignature jadesSignature = extractSignatureById(jwsJsonSerializationObject, parameters.getSignatureIdToCounterSign());
		
		List<Object> unsignedProperties = getUnsignedProperties(jadesSignature);
		
		addCSig(unsignedProperties, counterSignature, parameters.getJwsSerializationType());
		
		JWSJsonSerializationGenerator generator = new JWSJsonSerializationGenerator(jwsJsonSerializationObject, 
				jwsJsonSerializationObject.getJWSSerializationType());
		return new InMemoryDocument(generator.generate());
	}
	
	@SuppressWarnings("unchecked")
	private void addCSig(List<Object> unsignedProperties, DSSDocument counterSignature, JWSSerializationType jwsSerializationType) {
		JSONObject cSigItem = new JSONObject();
		
		String signatureString = new String(DSSUtils.toByteArray(counterSignature));
		
		Object cSig;
		switch (jwsSerializationType) {
			case COMPACT_SERIALIZATION:
				cSig = signatureString;
				break;
			case FLATTENED_JSON_SERIALIZATION:
				try {
					cSig = new JsonObject(JsonUtil.parseJson(signatureString));
				} catch (JoseException e) {
					throw new DSSException(String.format("An error occurred during a Counter Signature creation. Reason : %s", e.getMessage()), e);
				}
				break;
			default:
				throw new DSSException(String.format("The JWSSerializarionType '%s' is not supported for a Counter Signature!", 
						jwsSerializationType));
		}
		cSigItem.put(JAdESHeaderParameterNames.C_SIG, cSig);
		unsignedProperties.add(cSigItem);
	}
	
	private JAdESSignature extractSignatureById(JWSJsonSerializationObject jwsJsonSerializationObject, String signatureId) {
		if (!jwsJsonSerializationObject.isValid()) {
			throw new DSSException(String.format("Counter signature is not supported for invalid RFC 7515 files "
					+ "(shall be a Serializable JAdES signature). Reason(s) : %s",
					jwsJsonSerializationObject.getStructuralValidationErrors()));
		}
		if (Utils.isStringEmpty(signatureId)) {
			throw new DSSException("The Id of a signature to be counter signed shall be defined! "
					+ "Please use SerializableCounterSignatureParameters.setSignatureIdToCounterSign(signatureId) method.");
		}
		
		List<JWS> jwsSignatures = jwsJsonSerializationObject.getSignatures();
		if (Utils.isCollectionEmpty(jwsSignatures)) {
			throw new DSSException("The provided signatureDocument does not contain JAdES Signatures!");
		}
		for (JWS jws : jwsSignatures) {
			JAdESSignature jadesSignature = new JAdESSignature(jws);
			JAdESSignature signatureById = getSignatureOrItsCounterSignature(jadesSignature, signatureId);
			if (signatureById != null) {
				return signatureById;
			}
		}
		throw new DSSException(String.format("The requested JAdES Signature with id '%s' has not been found in the provided file!", signatureId));
	}

	@SuppressWarnings("unchecked")
	private JAdESSignature getSignatureOrItsCounterSignature(JAdESSignature signature, String signatureId) {
		if (signatureId == null || signatureId.equals(signature.getId())) {
			return signature;
		}

		List<Object> cSigObjects = DSSJsonUtils.getUnsignedProperties(signature.getJws(), JAdESHeaderParameterNames.C_SIG);
		if (Utils.isCollectionNotEmpty(cSigObjects)) {
			for (int ii = 0; ii < cSigObjects.size(); ii++)  {
				
				Object cSigObject = cSigObjects.get(ii);
				JAdESSignature counterSignature = DSSJsonUtils.extractJAdESCounterSignature(cSigObject, signature);
				if (counterSignature != null) {
					// check timestamp before incorporating a new property
					if (signature.getTimestampSource().isTimestamped(signatureId, TimestampedObjectType.SIGNATURE)) {
						throw new DSSException(String.format("Unable to counter sign a signature with Id '%s'. "
								+ "The signature is timestamped by a master signature!", signatureId));
					}

					if (cSigObject instanceof Map<?, ?>) {
						addUnprotectedHeader((Map<String, Object>) cSigObject, counterSignature.getJws());
					} else {
						String errorMessage = String.format("Unable to extend a Compact JAdES Signature with id '%s'", signatureId);
						if (signatureId.equals(counterSignature.getId())) {
							throw new DSSException(errorMessage);
						} else {
							LOG.warn("{}. The signature is skipped.", errorMessage);
							continue;
						}
					}
					
					JAdESSignature signatureById = getSignatureOrItsCounterSignature(counterSignature, signatureId);
					if (signatureById != null) {
						return signatureById;
					}
				}
			}
		}
		
		return null;
	}
	
	@SuppressWarnings("unchecked")
	private void addUnprotectedHeader(Map<String, Object> cSigMap, JWS jws) {
		Map<String, Object> unprotected = (Map<String, Object>) cSigMap.get(JWSConstants.HEADER);
		if (unprotected == null) {
			unprotected = new HashMap<>();
			cSigMap.put(JWSConstants.HEADER, unprotected);
		}
		jws.setUnprotected(unprotected);
	}

}
