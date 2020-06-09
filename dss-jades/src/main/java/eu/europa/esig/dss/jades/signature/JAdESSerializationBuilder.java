package eu.europa.esig.dss.jades.signature;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;

import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class JAdESSerializationBuilder extends AbstractJAdESBuilder {
	
	public JAdESSerializationBuilder(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters, 
			final List<DSSDocument> documentsToSign) {
		super(certificateVerifier, parameters, documentsToSign);
	}

	@Override
	public byte[] build(SignatureValue signatureValue) {
		assertConfigurationValidity(parameters);
		
		JWS jws = new JWS();
		incorporateHeader(jws);
		incorporatePayload(jws);
		
		Map<String, Object> jsonSerializationMap = new LinkedHashMap<>();
		jsonSerializationMap.put(JWSConstants.PAYLOAD, jws.getEncodedPayload());
		
		List<JSONObject> signatureList = new ArrayList<>();
		
		Map<String, Object> signatureMap = new LinkedHashMap<>();
		signatureMap.put(JWSConstants.PROTECTED, jws.getEncodedHeader());
		// jsonSerializationMap.put(JWSConstants.HEADER, getUnprotectedParameters());
		signatureMap.put(JWSConstants.SIGNATURE, JAdESUtils.toBase64Url(signatureValue.getValue()));

		signatureList.add(new JSONObject(signatureMap));
		
		jsonSerializationMap.put(JWSConstants.SIGNATURES, new JSONArray(signatureList));
		
		JSONObject jsonSignature = new JSONObject(jsonSerializationMap);
		return jsonSignature.toJSONString().getBytes();
	}

	@Override
	public MimeType getMimeType() {
		return MimeType.JOSE_JSON;
	}


	@Override
	protected void assertConfigurationValidity(JAdESSignatureParameters signatureParameters) {
		SignaturePackaging packaging = signatureParameters.getSignaturePackaging();
		if ((packaging != SignaturePackaging.ENVELOPING)) {
			throw new DSSException("Unsupported signature packaging for JSON Serialization Signature: " + packaging);
		}
	}

}
