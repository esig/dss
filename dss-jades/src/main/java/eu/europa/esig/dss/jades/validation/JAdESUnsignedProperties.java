package eu.europa.esig.dss.jades.validation;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureProperties;

public class JAdESUnsignedProperties implements SignatureProperties<JAdESAttribute> {

	private final List<Object> etsiU;

	public JAdESUnsignedProperties(List<Object> etsiU) {
		this.etsiU = etsiU;
	}

	@Override
	public boolean isExist() {
		return Utils.isCollectionNotEmpty(etsiU);
	}

	@Override
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public List<JAdESAttribute> getAttributes() {
		List<JAdESAttribute> attributes = new ArrayList<>();
		for (Object item : etsiU) {
			if (item instanceof Map) {
				Map jsonObject = (Map) item;
				Iterator iterator = jsonObject.entrySet().iterator();
				while (iterator.hasNext()) {
					Entry<String, Object> entry = (Entry<String, Object>) iterator.next();
					attributes.add(new JAdESAttribute(entry.getKey(), entry.getValue()));
				}
			}
		}
		return attributes;
	}

}
