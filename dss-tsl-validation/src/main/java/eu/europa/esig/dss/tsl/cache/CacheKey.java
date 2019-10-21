package eu.europa.esig.dss.tsl.cache;

import java.util.Objects;

import eu.europa.esig.dss.spi.DSSUtils;

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
