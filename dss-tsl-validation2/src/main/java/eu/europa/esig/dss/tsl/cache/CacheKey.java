package eu.europa.esig.dss.tsl.cache;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CacheKey {

	private static final Logger LOG = LoggerFactory.getLogger(CacheKey.class);
	
	/**
	 * Country code of the entry
	 */
	private String countryCode;
	
	/**
	 * Key of the entry
	 */
	private String key;
	
	/**
	 * The default constructor of CacheKey
	 * @param countryCode {@link String} country code of the entry
	 * @param fileUrl {@link String} url string of the related file entry
	 */
	public CacheKey(final String countryCode, final String fileUrl) {
		this.countryCode = countryCode;
		this.key = decodeString(fileUrl);
	}
	
	private String decodeString(String url) {
		String decodedUrl = url;
		try {
			decodedUrl = URLDecoder.decode(url, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			LOG.debug("Cannot decode url [{}]. Reason : {}", url, e.getMessage());
		}
		return decodedUrl.replaceAll("\\W", "_");
	}
	
	/**
	 * Returns country code of the entry
	 * @return {@link String} country code
	 */
	public String getCountryCode() {
		return countryCode;
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
		return String.format("CacheKey for country [%s] with the key [%s]", countryCode, key);
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
		if (countryCode == null && k.countryCode != null) {
			return false;
		} else if (!countryCode.equals(k.countryCode)) {
			return false;
		}
		return key.equals(k.key);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((countryCode == null) ? 0 : countryCode.hashCode());
		result = prime * result + ((key == null) ? 0 : key.hashCode());
		return result;
	}

}
