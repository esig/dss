package eu.europa.esig.dss.jades.requirements;

import java.util.Map;

import org.jose4j.json.JsonUtil;

public abstract class AbstractJAdESFlattenedSerializationRequirementsCheck extends AbstractJAdESRequirementsCheck {
	
	@Override
	protected String getPayload(byte[] byteArray) throws Exception {
		Map<String, Object> jsonMap = JsonUtil.parseJson(new String(byteArray));
		return (String) jsonMap.get("payload");
	}
	
	@Override
	protected String getProtectedHeader(byte[] byteArray) throws Exception {
		Map<String, Object> jsonMap = JsonUtil.parseJson(new String(byteArray));
		return (String) jsonMap.get("protected");
	}
	
	@Override
	protected String getSignatureValue(byte[] byteArray) throws Exception {
		Map<String, Object> jsonMap = JsonUtil.parseJson(new String(byteArray));
		return (String) jsonMap.get("signature");
	}
	
	@Override
	protected Map<?, ?> getUnprotectedHeader(byte[] byteArray) throws Exception {
		Map<String, Object> jsonMap = JsonUtil.parseJson(new String(byteArray));
		return (Map<?, ?>) jsonMap.get("header");
	}

}
