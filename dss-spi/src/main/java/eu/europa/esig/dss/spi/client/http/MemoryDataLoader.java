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
package eu.europa.esig.dss.spi.client.http;

import eu.europa.esig.dss.model.DSSException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Defines a map between URL and document to load the data from offline source
 */
public class MemoryDataLoader implements DataLoader {

	private static final long serialVersionUID = -2899281917849499181L;

	/** The map between URLs and the corresponding binary content */
	private Map<String, byte[]> dataMap = new HashMap<>();

	/**
	 * Default constructor
	 *
	 * @param dataMap a map between URLs and the corresponding binary content
	 */
	public MemoryDataLoader(Map<String, byte[]> dataMap) {
		this.dataMap.putAll(dataMap);
	}

	@Override
	public byte[] get(String url) {
		return dataMap.get(url);
	}

	@Override
	public DataAndUrl get(List<String> urlStrings) throws DSSException {
		for (String url : urlStrings) {
			byte[] data = get(url);
			if (data != null) {
				return new DataAndUrl(data, url);
			}
		}
		throw new DSSException(String.format("A content for URLs [%s] does not exist!", urlStrings));
	}

	@Override
	public byte[] get(String url, boolean refresh) {
		return get(url);
	}

	@Override
	public byte[] post(String url, byte[] content) {
		return get(url);
	}

	@Override
	public void setContentType(String contentType) {
	}

}
