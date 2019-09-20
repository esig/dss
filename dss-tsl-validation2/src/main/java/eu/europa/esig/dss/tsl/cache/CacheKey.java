package eu.europa.esig.dss.tsl.cache;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CacheKey {

	private static final Logger LOG = LoggerFactory.getLogger(CacheKey.class);
	
	/**
	 * Key of the entry
	 */
	private final String key;
	
	/**
	 * The default constructor of CacheKey
	 * @param url {@link String} url string of the related file entry
	 */
	public CacheKey(final String url) {
		this.key = decodeString(url);
	}
	
	private String decodeString(final String url) {
		String decodedUrl = url;
		try {
			decodedUrl = URLDecoder.decode(url, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			LOG.debug("Cannot decode url [{}]. Reason : {}", url, e.getMessage());
		}
		return decodedUrl.replaceAll("\\W", "_");
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
