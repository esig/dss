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
package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.spi.DSSUtils;

import java.util.Objects;

/**
 * Defines a key for a cache record
 */
public class CacheKey {

	/**
	 * Key of the entry
	 */
	private final String key;

	/**
	 * The default constructor of CacheKey
	 * 
	 * @param url
	 *            {@link String} url string of the related file entry
	 */
	public CacheKey(final String url) {
		Objects.requireNonNull(url, "URL cannot be null.");
		this.key = DSSUtils.getNormalizedString(url);
	}

	/**
	 * Returns encoded key
	 * 
	 * @return {@link String} key
	 */
	public String getKey() {
		return key;
	}

	@Override
	public String toString() {
		return String.format("CacheKey with the key [%s]", key);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((key == null) ? 0 : key.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		CacheKey other = (CacheKey) obj;
		if (key == null) {
			if (other.key != null) {
				return false;
			}
		} else if (!key.equals(other.key)) {
			return false;
		}
		return true;
	}

}
