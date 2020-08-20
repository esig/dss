package eu.europa.esig.dss.jades;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

/**
 * The Parser used to create a {@code JWSJsonSerializationObject} from a document
 *
 */
public class JWSJsonSerializationParser {
	
	/** The document to be parsed */
	private final DSSDocument document;

	/**
	 * The default constructor for parser to extract a list of signatures and payload
	 * 
	 * @param document {@link DSSDocument} to parse
	 */
	public JWSJsonSerializationParser(final DSSDocument document) {
		this.document = document;
	}
	
	/**
	 * Parses the provided document and returns JWSJsonSerializationObject if applicable
	 * 
	 * @return {@link JWSJsonSerializationObject}
	 */
	public JWSJsonSerializationObject parse() {
		try {
			Map<String, Object> rootStructure = JsonUtil.parseJson(new String(DSSUtils.toByteArray(document)));
			
			JWSJsonSerializationObject jwsJsonSerializationObject = new JWSJsonSerializationObject();

			Object payloadObject = rootStructure.get(JWSConstants.PAYLOAD);
			if (payloadObject instanceof String) {
				String payload = (String) payloadObject;
				jwsJsonSerializationObject.setPayload(payload);
			} else if (payloadObject != null) {
				jwsJsonSerializationObject.addErrorMessage("The 'payload' must be instance of String class!");
			}
			
			// try to extract complete JWS JSON Serialization signatures
			Object signaturesObject = rootStructure.get(JWSConstants.SIGNATURES);
			if (signaturesObject != null) {
				jwsJsonSerializationObject.setJWSSerializationType(JWSSerializationType.JSON_SERIALIZATION);
				checkForAllowedElements(jwsJsonSerializationObject, rootStructure, 
						JWSConstants.PAYLOAD, JWSConstants.SIGNATURES);
				
				extractSignatures(jwsJsonSerializationObject, signaturesObject);
			} else {
				// otherwise extract flattened JWS JSON Serialization signature
				jwsJsonSerializationObject.setJWSSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
				
				checkForAllowedElements(jwsJsonSerializationObject, rootStructure, 
						JWSConstants.PAYLOAD, JWSConstants.SIGNATURE, JWSConstants.HEADER, JWSConstants.PROTECTED);
				
				extractSignature(jwsJsonSerializationObject, rootStructure);
			}
			
			return jwsJsonSerializationObject;
			
		} catch (JoseException e) {
			throw new DSSException(String.format("Unable to parse document with name '%s'. "
					+ "Reason : %s", document.getName(), e.getMessage()), e);
		}
	}
	
	/**
	 * Verifies if the given document is supported by the parser
	 * 
	 * @return TRUE of the document is supported and can be parsed, FALSE otherwise
	 */
	public boolean isSupported() {
		return JAdESUtils.isJsonDocument(document);
	}

	@SuppressWarnings("unchecked")
	private void extractSignatures(JWSJsonSerializationObject jwsJsonSerializationObject, Object signaturesObject) {
		if (signaturesObject instanceof List<?>) {
			List<Object> signaturesObjectList = (List<Object>) signaturesObject;
			if (Utils.isCollectionNotEmpty(signaturesObjectList)) {
				for (Object signatureObject : signaturesObjectList) {
					if (signatureObject instanceof Map<?, ?>) {
						Map<String, Object> signatureMap = (Map<String, Object>) signatureObject;
						
						checkForAllowedElements(jwsJsonSerializationObject, signatureMap, 
								JWSConstants.SIGNATURE, JWSConstants.HEADER, JWSConstants.PROTECTED);
						
						extractSignature(jwsJsonSerializationObject, signatureMap);
					} else if (signatureObject != null) {
						jwsJsonSerializationObject.addErrorMessage("The element in 'signatures' list shall be a JSON Map!");
					}
				}
			} else {
				jwsJsonSerializationObject.addErrorMessage("The 'signatures' element must not be empty!");
			}
		} else {
			jwsJsonSerializationObject.addErrorMessage("The 'signatures' element must be a list of objects!");
		}
	}
	
	@SuppressWarnings("unchecked")
	private void extractSignature(JWSJsonSerializationObject jwsJsonSerializationObject, Map<String, Object> signatureMap) {
		try {
			JWS signature = new JWS();
			
			Object signatureObject = signatureMap.get(JWSConstants.SIGNATURE);
			if (signatureObject == null) {
				jwsJsonSerializationObject.addErrorMessage("The 'signature' element is not present!");
				return;
			}
			if (signatureObject instanceof String) {
				String signatureBase64Url = (String) signatureObject;
				if (Utils.isStringBlank(signatureBase64Url)) {
					jwsJsonSerializationObject.addErrorMessage("The 'signature' element content cannot be blank!");
					return;
				}
				signature.setSignature(JAdESUtils.fromBase64Url(signatureBase64Url));
			} else {
				jwsJsonSerializationObject.addErrorMessage("The 'signature' element must be of String type!");
			}
			
			Object protectedObject = signatureMap.get(JWSConstants.PROTECTED);
			if (protectedObject instanceof String) {
				String protectedBase64Url = (String) protectedObject;
				signature.setProtected(protectedBase64Url);
			} else if (protectedObject != null) {
				jwsJsonSerializationObject.addErrorMessage("The 'protected' element must be of String type!");
			}
			
			Object headerObject = signatureMap.get(JWSConstants.HEADER);
			if (headerObject instanceof Map<?, ?>) {
				Map<String, Object> header = (Map<String, Object>) headerObject;
				signature.setUnprotected(header);
			} else if (headerObject != null) {
				jwsJsonSerializationObject.addErrorMessage("The 'header' element must be of JSON Map type!");
			}
			
			if (signature.isRfc7797UnencodedPayload()) {
				signature.setPayloadBytes(jwsJsonSerializationObject.getPayload().getBytes(StandardCharsets.UTF_8));
			} else {
				signature.setPayloadBytes(JAdESUtils.fromBase64Url(jwsJsonSerializationObject.getPayload()));
			}

			signature.setJwsJsonSerializationObject(jwsJsonSerializationObject);
			jwsJsonSerializationObject.getSignatures().add(signature);
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to build a signature. Reason : [%s]", e.getMessage()), e);
		}
	}
	
	private void checkForAllowedElements(JWSJsonSerializationObject jwsJsonSerializationObject, Map<String, Object> map, String... allowedKeys) {
		for (String keyName : map.keySet()) {
			boolean match = Arrays.stream(allowedKeys).anyMatch(keyName::equals);
			if (!match) {
				jwsJsonSerializationObject.addErrorMessage(String.format("The file contains not allowed for JWS element with name : '%s'. "
						+ "The following elements are allowed only on the level : %s", keyName, Arrays.toString(allowedKeys)));
			}
		}
	}

}
