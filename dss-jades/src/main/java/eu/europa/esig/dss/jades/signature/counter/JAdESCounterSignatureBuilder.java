package eu.europa.esig.dss.jades.signature.counter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.lang.JoseException;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.JWSJsonSerializationGenerator;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.jades.signature.JAdESExtensionBuilder;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

public class JAdESCounterSignatureBuilder extends JAdESExtensionBuilder {
	
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
					+ "(shall be a Serializable JAdES signature). Reason(s) : %s", jwsJsonSerializationObject.getErrorMessages()));
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
	
	private JAdESSignature getSignatureOrItsCounterSignature(JAdESSignature signature, String signatureId) {
		if (signatureId == null || signatureId.equals(signature.getId())) {
			return signature;
		}

		List<Object> cSigObjects = JAdESUtils.getUnsignedProperties(signature.getJws(), JAdESHeaderParameterNames.C_SIG);
		if (Utils.isCollectionNotEmpty(cSigObjects)) {
			for (Object cSigObject : cSigObjects) {
				
				JAdESSignature counterSignature = JAdESUtils.extractJAdESCounterSignature(cSigObject, signature);
				if (counterSignature != null) {
					addUnprotectedHeader(cSigObject, counterSignature.getJws());
					
					JAdESSignature signatureById = getSignatureOrItsCounterSignature(counterSignature, signatureId);
					if (signatureById != null) {
						if (isTimestamped(signatureById)) {
							throw new DSSException(String.format("Unable to counter sign a signature with Id '%s'. "
									+ "The signature is timestamped by a master signature!", signatureId));
						}
						return signatureById;
					}
				}
			}
		}
		
		return null;
	}
	
	@SuppressWarnings("unchecked")
	private void addUnprotectedHeader(Object cSigObject, JWS jws) {
		if (cSigObject instanceof Map<?, ?>) {
			Map<String, Object> cSigMap = (Map<String, Object>) cSigObject;
			Map<String, Object>  unprotected = (Map<String, Object>) cSigMap.get(JWSConstants.HEADER);
			if (unprotected == null) {
				unprotected = new HashMap<String, Object>();
				cSigMap.put(JWSConstants.HEADER, unprotected);
			}
			jws.setUnprotected(unprotected);
		}
	}
	
	private boolean isTimestamped(AdvancedSignature signature) {
		AdvancedSignature masterSignature = signature.getMasterSignature();
		if (masterSignature != null) {
			for (TimestampToken timestampToken : masterSignature.getArchiveTimestamps()) {
				if (timestampToken.getTimestampedReferences().contains(new TimestampedReference(signature.getId(), TimestampedObjectType.SIGNATURE))) {
					return true;
				}
			}
			return isTimestamped(masterSignature);
		}
		return false;
	}

}
