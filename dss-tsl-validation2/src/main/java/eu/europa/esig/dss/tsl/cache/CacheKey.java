package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.spi.DSSUtils;

public class CacheKey {
	
	/**
	 * Key of the entry
	 */
	private final String key;
	
	/**
	 * The default constructor of CacheKey
	 * @param url {@link String} url string of the related file entry
	 */
	public CacheKey(final String url) {
		this.key = DSSUtils.getNormalizedString(url);
	}
	
	/**
	 * Returns encoded key
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
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof CacheKey)) {
			return false;
		}
		CacheKey k = (CacheKey) obj;
		return key.equals(k.key);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((key == null) ? 0 : key.hashCode());
		return result;
	}

}
