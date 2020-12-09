package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.SignatureProperties;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwx.Headers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Represents a list of JAdES signed properties (protected header)
 */
public class JAdESSignedProperties implements SignatureProperties<JAdESAttribute> {

	/** Represent the protected header map */
	private final Headers headers;

	/**
	 * Default constructor
	 *
	 * @param headers {@link Headers}
	 */
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
