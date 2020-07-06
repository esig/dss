package eu.europa.esig.dss.jades.validation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureProperties;

public class JAdESUnsignedProperties implements SignatureProperties<JAdESAttribute> {

	private final Map<String, Object> etsiU;

	public JAdESUnsignedProperties(Map<String, Object> etsiU) {
		this.etsiU = etsiU;
	}

	@Override
	public boolean isExist() {
		return Utils.isMapNotEmpty(etsiU);
	}

	@Override
	public List<JAdESAttribute> getAttributes() {
		List<JAdESAttribute> attributes = new ArrayList<>();
		for (Entry<String, Object> etsiUEntry : etsiU.entrySet()) {
			attributes.add(new JAdESAttribute(etsiUEntry.getKey(), etsiUEntry.getValue()));
		}
		return attributes;
	}

}
