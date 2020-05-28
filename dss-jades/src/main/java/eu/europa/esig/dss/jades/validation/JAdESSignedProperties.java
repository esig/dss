package eu.europa.esig.dss.jades.validation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwx.Headers;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.SignatureProperties;

public class JAdESSignedProperties implements SignatureProperties<JAdESAttribute> {

	private final Headers headers;

	public JAdESSignedProperties(Headers headers) {
		this.headers = headers;
	}

	@Override
	public boolean isExist() {
		return headers != null;
	}

	@Override
	public List<JAdESAttribute> getAttributes() {
		List<JAdESAttribute> attributes = new ArrayList<>();

		Map<String, Object> headerMap = getMapKeyValues();

		for (Entry<String, Object> entry : headerMap.entrySet()) {
			attributes.add(new JAdESAttribute(entry.getKey(), entry.getValue()));
		}

		return attributes;
	}

	private Map<String, Object> getMapKeyValues() {
		try {
			// TODO avoid to parse
			return JsonUtil.parseJson(headers.getFullHeaderAsJsonString());
		} catch (Exception e) {
			throw new DSSException("Unable to retrieve the map from the headers", e);
		}
	}

}
