package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.validation.ISignatureAttribute;

public class JAdESAttribute implements ISignatureAttribute {

	protected String name;
	protected Object value;

	JAdESAttribute() {
	}

	public JAdESAttribute(String name, Object value) {
		this.name = name;
		this.value = value;
	}

	public String getHeaderName() {
		return name;
	}

	public Object getValue() {
		return value;
	}
	
}
