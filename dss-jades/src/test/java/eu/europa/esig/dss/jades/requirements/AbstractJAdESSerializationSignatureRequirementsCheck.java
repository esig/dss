package eu.europa.esig.dss.jades.requirements;

import java.util.List;
import java.util.Map;

import org.jose4j.json.JsonUtil;

public abstract class AbstractJAdESSerializationSignatureRequirementsCheck extends AbstractJAdESRequirementsCheck {
	
	@Override
	protected String getPayload(byte[] byteArray) throws Exception {
		Map<String, Object> jsonMap = JsonUtil.parseJson(new String(byteArray));
		return (String) jsonMap.get("payload");
	}
	
	@Override
	protected String getProtectedHeader(byte[] byteArray) throws Exception {
		Map<?, ?> signature = getSignature(byteArray);
		return (String) signature.get("protected");
	}
	
	@Override
	protected String getSignatureValue(byte[] byteArray) throws Exception {
		Map<?, ?> signature = getSignature(byteArray);
		return (String) signature.get("signature");
	}
	
	@Override
	protected Map<?, ?> getUnprotectedHeader(byte[] byteArray) throws Exception {
		Map<?, ?> signature = getSignature(byteArray);
		return (Map<?, ?>) signature.get("header");
	}
	
	private Map<?, ?> getSignature(byte[] byteArray) throws Exception {
		Map<String, Object> jsonMap = JsonUtil.parseJson(new String(byteArray));
		List<?> signaturesList = (List<?>) jsonMap.get("signatures");
		return (Map<?, ?>) signaturesList.get(0);
	}

}
