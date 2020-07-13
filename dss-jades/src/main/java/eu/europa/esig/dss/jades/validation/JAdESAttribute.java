package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.validation.ISignatureAttribute;

public class JAdESAttribute implements ISignatureAttribute {

	private final String key;
	private final Object value;

	public JAdESAttribute(String key, Object value) {
		this.key = key;
		this.value = value;
	}

	public String getHeaderName() {
		return key;
	}

	public Object getValue() {
		return value;
	}
	
	public int getValueHashCode() {
		return value.hashCode();
	}
	
}
