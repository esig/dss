package eu.europa.esig.dss.jades.signature;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JsonSerializationSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

/**
 * Builds a JWS JSON Serialization signature
 *
 */
public class JAdESSerializationBuilder extends AbstractJAdESBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESSerializationBuilder.class);
	
	private JWSJsonSerializationObject jwsJsonSerializationObject;
	
	public JAdESSerializationBuilder(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters, 
			final List<DSSDocument> documentsToSign) {
		super(certificateVerifier, parameters, documentsToSign);
	}
	
	public JAdESSerializationBuilder(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters,
			final JWSJsonSerializationObject jwsJsonSerializationObject) {
		super(certificateVerifier, parameters, extractDocumentToBeSigned(parameters, jwsJsonSerializationObject));
		this.jwsJsonSerializationObject = jwsJsonSerializationObject;
	}
	
	private static List<DSSDocument> extractDocumentToBeSigned(JAdESSignatureParameters parameters, 
			JWSJsonSerializationObject jwsJsonSerializationObject) {
		if (Utils.isStringNotBlank(jwsJsonSerializationObject.getPayload())) {
			// enveloping signature
			try {
				JsonSerializationSignature signature = jwsJsonSerializationObject.getSignatures().get(0);
				JWS jws = new JWS();
				jws.setProtected(signature.getBase64UrlProtectedHeader());
				
				byte[] payloadBytes;
				if (jws.isRfc7797UnencodedPayload()) {
					payloadBytes = jwsJsonSerializationObject.getPayload().getBytes();
				} else {
					payloadBytes = JAdESUtils.fromBase64Url(jwsJsonSerializationObject.getPayload());
				}
				return Collections.singletonList(new InMemoryDocument(payloadBytes));
			} catch (JoseException e) {
				throw new DSSException("The document contains a signature with an invalid content! Unable to sign/extend.");
			}
			
		} else if (Utils.isCollectionNotEmpty(parameters.getDetachedContents())) {
			// detached signature
			return parameters.getDetachedContents();
			
		} else {
			throw new DSSException("The payload or detached content must be provided!");
		}
	}

	@Override
	public byte[] build(SignatureValue signatureValue) {
		assertConfigurationValidity(parameters);
		
		JWS jws = getJWS();
		
		if (jwsJsonSerializationObject == null) {
			jwsJsonSerializationObject = new JWSJsonSerializationObject();
			jwsJsonSerializationObject.setPayload(jws.getSignedPayload());
		} else {
			assertB64ConfigurationConsistent();
		}
		
		JsonSerializationSignature jsonSerializationSignature = new JsonSerializationSignature();
		jsonSerializationSignature.setBase64UrlProtectedHeader(jws.getEncodedHeader());
		// jsonSerializationSignature.setUnprotected(getUnprotectedParameters());
		jsonSerializationSignature.setBase64UrlSignature(JAdESUtils.toBase64Url(signatureValue.getValue()));
		
		jwsJsonSerializationObject.getSignatures().add(jsonSerializationSignature);
		
		JSONObject jsonSerialization;
		switch (parameters.getJwsSerializationType()) {
			case JSON_SERIALIZATION:
				jsonSerialization = buildJWSJsonSerialization();
				break;
			case FLATTENED_JSON_SERIALIZATION:
				jsonSerialization = buildFlattenedJwsJsonSerialization();
				break;
			default:
				throw new DSSException(String.format("The JAdESSerializationBuilder does not support the given JWS Serialziation Type '%s'", 
						parameters.getJwsSerializationType()));
		}
		
		return jsonSerialization.toJSONString().getBytes();
	}
	
	/**
	 * All not detached signatures must have the same 'b64' value
	 */
	private void assertB64ConfigurationConsistent() {
		// verify only for non-detached cases
		if (!SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
			try {
				boolean base64UrlEncodedPayload = parameters.isBase64UrlEncodedPayload();
				for (JsonSerializationSignature signature : jwsJsonSerializationObject.getSignatures()) {
					JWS jws = new JWS();
					jws.setProtected(signature.getBase64UrlProtectedHeader());
					if (base64UrlEncodedPayload != !jws.isRfc7797UnencodedPayload()) {
						throw new DSSException("'b64' value shall be the same for all signatures!");
					}
				}
			} catch (JoseException e) {
				throw new DSSException(String.format("Unable to verify protected header of existing signatures. Reason : %s", e.getMessage()), e);
			}
		}
	}
	
	private JSONObject buildJWSJsonSerialization() {
		if (jwsJsonSerializationObject.isFlattened()) {
			LOG.warn("A flattened signature will be transformed to a Complete JWS JSON Serialization Format!");
		}
		
		Map<String, Object> jsonSerializationMap = new LinkedHashMap<>();
		
		String payload = jwsJsonSerializationObject.getPayload();
		if (Utils.isStringNotBlank(payload)) {
			jsonSerializationMap.put(JWSConstants.PAYLOAD, jwsJsonSerializationObject.getPayload());
		}
		
		List<JSONObject> signatureList = new ArrayList<>();
		for (JsonSerializationSignature signature : jwsJsonSerializationObject.getSignatures()) {
			Map<String, Object> signatureMap = getSignatureJsonMap(signature);
			signatureList.add(new JSONObject(signatureMap));
		}
		jsonSerializationMap.put(JWSConstants.SIGNATURES, new JSONArray(signatureList));
		
		return new JSONObject(jsonSerializationMap);
	}
	
	private JSONObject buildFlattenedJwsJsonSerialization() {		
		Map<String, Object> flattenedJwsMap = new LinkedHashMap<>();
		String encodedPayload = jwsJsonSerializationObject.getPayload();
		if (Utils.isStringNotBlank(encodedPayload)) {
			flattenedJwsMap.put(JWSConstants.PAYLOAD, jwsJsonSerializationObject.getPayload());
		}
		
		JsonSerializationSignature jsonSerializationSignature = jwsJsonSerializationObject.getSignatures().get(0);
		Map<String, Object> signatureJsonMap = getSignatureJsonMap(jsonSerializationSignature);
		flattenedJwsMap.putAll(signatureJsonMap);
		
		return new JSONObject(flattenedJwsMap);
	}
	
	private JWS getJWS() {
		JWS jws = new JWS();
		incorporateHeader(jws);
		incorporatePayload(jws);
		return jws;
	}
	
	private Map<String, Object> getSignatureJsonMap(JsonSerializationSignature signature) {
		Map<String, Object> signatureMap = new LinkedHashMap<>();
		
		String encodedProtected = signature.getBase64UrlProtectedHeader();
		if (Utils.isStringNotBlank(encodedProtected)) {
			signatureMap.put(JWSConstants.PROTECTED, encodedProtected);
		}
		
		Map<String, Object> unprotected = signature.getUnprotected();
		if (Utils.isMapNotEmpty(unprotected)) {
			signatureMap.put(JWSConstants.HEADER, unprotected);
		}
		
		String encodedSignature = signature.getBase64UrlSignature();
		signatureMap.put(JWSConstants.SIGNATURE, encodedSignature);
		
		return signatureMap;
	}

	@Override
	public MimeType getMimeType() {
		return MimeType.JOSE_JSON;
	}

	@Override
	protected void assertConfigurationValidity(JAdESSignatureParameters signatureParameters) {
		SignaturePackaging packaging = signatureParameters.getSignaturePackaging();
		if ((packaging != SignaturePackaging.ENVELOPING) && (packaging != SignaturePackaging.DETACHED)) {
			throw new DSSException("Unsupported signature packaging for JSON Serialization Signature: " + packaging);
		}
		if (JWSSerializationType.FLATTENED_JSON_SERIALIZATION.equals(signatureParameters.getJwsSerializationType()) &&
				jwsJsonSerializationObject != null) {
			throw new DSSException("The FLATTENED Serialization type is not supported for a document with existing signatures!");
		}
	}

}
