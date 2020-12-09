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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * This class allows to avoid downloading resources.
 */
public class IgnoreDataLoader implements DataLoader {

	private static final long serialVersionUID = -1808691070503805042L;

	private static final Logger LOG = LoggerFactory.getLogger(IgnoreDataLoader.class);

	/** Default error message */
	private static final String URL_IS_IGNORED = "Url '{}' is ignored";

	@Override
	public byte[] get(String url) {
		LOG.debug(URL_IS_IGNORED, url);
		return null;
	}

	@Override
	public DataAndUrl get(List<String> urlStrings) {
		LOG.debug("Urls {} are ignored", urlStrings);
		return null;
	}

	@Override
	public byte[] get(String url, boolean refresh) {
		LOG.debug(URL_IS_IGNORED, url);
		return null;
	}

	@Override
	public byte[] post(String url, byte[] content) {
		LOG.debug(URL_IS_IGNORED, url);
		return null;
	}

	@Override
	public void setContentType(String contentType) {
	}

}
