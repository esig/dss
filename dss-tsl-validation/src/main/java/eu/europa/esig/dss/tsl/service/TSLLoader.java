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
package eu.europa.esig.dss.tsl.service;

import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.tsl.TSLLoaderResult;

/**
 * This class allows to load binaries from an url with a DataLoader. It can be executed as a Callable.
 *
 */
public class TSLLoader implements Callable<TSLLoaderResult> {

	private static final Logger LOG = LoggerFactory.getLogger(TSLLoader.class);

	private DataLoader dataLoader;
	private String countryCode;
	private String urlToLoad;

	public TSLLoader(DataLoader dataLoader, String countryCode, String urlToLoad) {
		this.dataLoader = dataLoader;
		this.countryCode= countryCode;
		this.urlToLoad = urlToLoad;
	}

	@Override
	public TSLLoaderResult call() throws Exception {
		TSLLoaderResult result = new TSLLoaderResult();
		result.setCountryCode(countryCode);
		result.setUrl(urlToLoad);
		try {
			byte[] byteArray = dataLoader.get(urlToLoad);
			result.setContent(byteArray);
		} catch (Exception e) {
			LOG.warn("Unable to load '{}' : {}", urlToLoad, e.getMessage());
		}

		return result;
	}

}
