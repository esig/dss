package eu.europa.esig.dss.jades;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

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
	
	@SuppressWarnings("unchecked")
	public JWSJsonSerializationObject parse() {
		try {
			Map<String, Object> rootStructure = JsonUtil.parseJson(new String(DSSUtils.toByteArray(document)));
			
			JWSJsonSerializationObject jwsJsonSerializationObject = new JWSJsonSerializationObject();
			

			String payload = (String) rootStructure.get(JWSConstants.PAYLOAD);
			jwsJsonSerializationObject.setPayload(payload);
			
			List<JsonSerializationSignature> signatures = new ArrayList<>();
			// try to extract complete JWS JSON Serialization signatures
			List<Map<String, Object>> signaturesList = (List<Map<String, Object>>) rootStructure.get(JWSConstants.SIGNATURES);
			if (Utils.isCollectionNotEmpty(signaturesList)) {
				for (Map<String, Object> signatureObject : signaturesList) {
					JsonSerializationSignature signature = getSignature(signatureObject);
					if (signature != null) {
						signatures.add(signature);
					}
				}
			} else {
				// otherwise extract flattened JWS JSON Serialization signature
				jwsJsonSerializationObject.setFlattened(true);
				
				JsonSerializationSignature signature = getSignature(rootStructure);
				if (signature != null) {
					signatures.add(signature);
				}
			}
			jwsJsonSerializationObject.setSignatures(signatures);
			
			return jwsJsonSerializationObject;
			
		} catch (JoseException e) {
			throw new DSSException(String.format("Unable to parse document with name '%s'. "
					+ "Reason : %s", document.getName(), e.getMessage()), e);
		}
	}
	
	@SuppressWarnings("unchecked")
	private JsonSerializationSignature getSignature(Map<String, Object> signatureObject) throws DSSException {
		try {
			JsonSerializationSignature signature = new JsonSerializationSignature();
			
			String signatureBase64Url = (String) signatureObject.get(JWSConstants.SIGNATURE);
			if (Utils.isStringBlank(signatureBase64Url)) {
				// the signature is not found
				return null;
			}
			signature.setBase64UrlSignature(signatureBase64Url);
			
			String protectedBase64Url = (String) signatureObject.get(JWSConstants.PROTECTED);
			signature.setBase64UrlProtectedHeader(protectedBase64Url);
			
			Map<String, Object> header = (Map<String, Object>) signatureObject.get(JWSConstants.HEADER);
			signature.setUnprotected(header);
			
			return signature;
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to build a signature. Reason : [%s]", e.getMessage()), e);
		}
	}

}
