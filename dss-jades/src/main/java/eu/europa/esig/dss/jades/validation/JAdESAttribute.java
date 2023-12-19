/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.validation.SignatureAttribute;

import java.util.Objects;

/**
 * Represents the JAdES header
 */
public class JAdESAttribute implements SignatureAttribute {

	private static final long serialVersionUID = -5225041807617983947L;
	
	/** Name if the header */
	protected String name;

	/** The component's value */
	protected Object value;

	/** Identifies the instance */
	protected JAdESAttributeIdentifier identifier;

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

	/**
	 * Gets the attribute identifier
	 *
	 * @return {@link JAdESAttributeIdentifier}
	 */
	@Override
	public JAdESAttributeIdentifier getIdentifier() {
		if (identifier == null) {
			identifier = JAdESAttributeIdentifier.build(name, value);
		}
		return identifier;
	}
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		JAdESAttribute that = (JAdESAttribute) o;

		return Objects.equals(getIdentifier(), that.getIdentifier());
	}

	@Override
	public int hashCode() {
		return getIdentifier() != null ? getIdentifier().hashCode() : 0;
	}

}
