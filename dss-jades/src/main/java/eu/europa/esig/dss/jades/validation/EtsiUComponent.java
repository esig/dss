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

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JsonObject;

/**
 * Represents an item of the 'etsiU' header array
 */
public class EtsiUComponent extends JAdESAttribute {

	/** If the component is a base64url encoded instance */
	private final boolean base64UrlEncoded;

	/** The hash-value of the original object */
	private final int hashValue;

	/** The component in its original representation */
	private Object component;

	/**
	 * The default constructor
	 *
	 * @param component {@link Object} the original component
	 * @param headerName {@link String} the header name
	 * @param value {@link Object} value
	 * @param order the order of the component in 'etsiU' array
	 */
	public EtsiUComponent(Object component, String headerName, Object value, int order) {
		super(headerName, value);
		this.component = component;
		this.base64UrlEncoded = DSSJsonUtils.isStringFormat(component);
		this.hashValue = component.hashCode() + order; // enforce different values for equal string components
	}

	/**
	 * Gets the attribute in its 'etsiU' member representation
	 * 
	 * @return 'etsiU' array's component
	 */
	public Object getComponent() {
		return component;
	}

	/**
	 * Gets if the component is base64url encoded
	 *
	 * @return TRUE if the component is represented in its base64url encoding, FALSE otherwise
	 */
	public boolean isBase64UrlEncoded() {
		return base64UrlEncoded;
	}

	/**
	 * Overwrites the value of the object
	 *
	 * @param value new object value
	 */
	public void overwriteValue(Object value) {
		this.value = value;
		this.component = recreateEtsiUComponent(name, value, base64UrlEncoded);
	}

	/**
	 * Returns an 'etsiU' component in the defined representation
	 * 
	 * @param name             {@link String} header name
	 * @param value            object
	 * @param base64UrlEncoded TRUE if base64Url encoded representation, FALSE
	 *                         otherwise
	 * @return 'etsiU' component
	 */
	public Object recreateEtsiUComponent(String name, Object value, boolean base64UrlEncoded) {
		JsonObject jsonObject = new JsonObject();
		jsonObject.put(name, value);
		return base64UrlEncoded ? DSSJsonUtils.toBase64Url(jsonObject) : jsonObject;
	}

	@Override
	public int hashCode() {
		return hashValue;
	}

}
