package eu.europa.esig.dss.jades.signature;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jose4j.json.internal.json_simple.JSONArray;

import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;

public abstract class JAdESExtensionBuilder {

	@SuppressWarnings("unchecked")
	protected List<Object> getUnsignedProperties(JAdESSignature jadesSignature) {
		JWS jws = jadesSignature.getJws();
		Map<String, Object> unprotected = jws.getUnprotected();
		if (unprotected == null) {
			unprotected = new HashMap<>();
			jws.setUnprotected(unprotected);
		}

		return (List<Object>) unprotected.computeIfAbsent(JAdESHeaderParameterNames.ETSI_U, k -> new JSONArray());
	}

}
