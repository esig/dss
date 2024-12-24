/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JsonObject;

import java.util.Map;

/**
 * Represents an item of the 'etsiU' header array
 */
public class EtsiUComponent extends JAdESAttribute {

	private static final long serialVersionUID = -4134366074771198071L;

	/** If the component is a base64url encoded instance */
	private final boolean base64UrlEncoded;

	/** The component in its original representation */
	private final Object component;

	/**
	 * Default constructor
	 *
	 * @param component represents the component of the 'etsiU' array
	 * @param headerName {@link String} header name of the component
	 * @param value represents the value of the component
	 * @param identifier {@link JAdESAttributeIdentifier}
	 */
	EtsiUComponent(Object component, String headerName, Object value, JAdESAttributeIdentifier identifier) {
		super(headerName, value);
		this.component = component;
		this.base64UrlEncoded = DSSJsonUtils.isStringFormat(component);
		this.identifier = identifier;
	}

	/**
	 * Builds {@code EtsiUComponent} from the 'etsiU' array entry
	 *
	 * @param component represents the component of the 'etsiU' array
	 * @param order defines the position number of the component in the 'etsiU' array
	 * @return {@link EtsiUComponent}
	 */
	public static EtsiUComponent build(Object component, int order) {
		Map<String, Object> map = DSSJsonUtils.parseEtsiUComponent(component);
		if (map != null) {
			Map.Entry<String, Object> mapEntry = map.entrySet().iterator().next();
			String headerName = mapEntry.getKey();
			Object value = mapEntry.getValue();
			JAdESAttributeIdentifier identifier = JAdESAttributeIdentifier.build(headerName, value, order);
			return new EtsiUComponent(component, headerName, value, identifier);
		}
		return null;
	}

	/**
	 * Builds the {@code EtsiUComponent} from the given parameters
	 *
	 * @param headerName {@link String} name of the 'etsiU' array component
	 * @param value represents the value of the component
	 * @param base64UrlEncoded defines if the components is stored in base64url encoding
	 * @param identifier {@link JAdESAttributeIdentifier}
	 * @return {@link EtsiUComponent}
	 */
	public static EtsiUComponent build(
			String headerName, Object value, boolean base64UrlEncoded, JAdESAttributeIdentifier identifier) {
		Object component = createEtsiUComponent(headerName, value, base64UrlEncoded);
		return new EtsiUComponent(component, headerName, value, identifier);
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
	private static Object createEtsiUComponent(String name, Object value, boolean base64UrlEncoded) {
		JsonObject jsonObject = new JsonObject();
		jsonObject.put(name, value);
		return base64UrlEncoded ? DSSJsonUtils.toBase64Url(jsonObject) : jsonObject;
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

}
