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
package eu.europa.esig.dss.client.http.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;

/**
 * This class uses a property file to read the proxy preferences.
 *
 *
 *
 *
 *
 *
 */
public class ProxyFileDao implements ProxyDao {

	private static final Logger LOG = LoggerFactory.getLogger(ProxyFileDao.class);

	protected Map<ProxyKey, ProxyPreference> proxyPreferences = new HashMap<ProxyKey, ProxyPreference>();

	public ProxyFileDao(final String proxyPreferencesResourcePath) {

		LOG.info(">>> ProxyFileDao: " + proxyPreferencesResourcePath);
		try {

			final InputStream propertyInputStream = DSSUtils.getResource(proxyPreferencesResourcePath);
			final Properties properties = new Properties();
			properties.load(propertyInputStream);
			for (final Map.Entry keySet : properties.entrySet()) {

				final String key = (String) keySet.getKey();
				final String value = (String) keySet.getValue();
				LOG.trace(key + "=" + (key.contains("password") ? "******" : value));
				final ProxyKey proxyKey = ProxyKey.fromKey(key);
				if (proxyKey == null) {
					continue;
				}
				final ProxyPreference proxyPreference = new ProxyPreference(proxyKey, value);
				proxyPreferences.put(proxyKey, proxyPreference);
			}
		} catch (IOException e) {
			throw new DSSException("Error when initialising ProxyFileDao", e);
		}
	}

	@Override
	public ProxyPreference get(final ProxyKey proxyKey) {

		final ProxyPreference proxyPreference = proxyPreferences.get(proxyKey);
		return proxyPreference;
	}

	@Override
	public Collection<ProxyPreference> getAll() {

		List<ProxyPreference> proxyPreferenceList = new ArrayList<ProxyPreference>(proxyPreferences.values());
		return proxyPreferenceList;
	}

	@Override
	public void update(final ProxyPreference proxyPreference) {

		proxyPreferences.put(proxyPreference.getProxyKey(), proxyPreference);
	}

	@Override
	public String toString() {
		return "ProxyFileDao{" +
			  "proxyPreferences=" + proxyPreferences +
			  '}';
	}
}
