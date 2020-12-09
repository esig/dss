package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.validation.ISignatureAttribute;

/**
 * Represents the JAdES header
 */
public class JAdESAttribute implements ISignatureAttribute {

	/** Name if the header */
	protected String name;

	/** The component's value */
	protected Object value;

	/**
	 * Default constructor
	 *
	 * @param name {@link String} header name
	 * @param value object's value
	 */
	public JAdESAttribute(String name, Object value) {
		this.name = name;
		this.value = value;
	}

	/**
	 * Gets the header's name
	 *
	 * @return {@link String}
	 */
	public String getHeaderName() {
		return name;
	}

	/**
	 * Gets the value
	 *
	 * @return value
	 */
	public Object getValue() {
		return value;
	}
	
}
