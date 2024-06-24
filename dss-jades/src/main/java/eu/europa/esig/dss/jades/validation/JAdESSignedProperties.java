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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.validation.SignatureProperties;
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

	private static final long serialVersionUID = 5541470950403288039L;

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
