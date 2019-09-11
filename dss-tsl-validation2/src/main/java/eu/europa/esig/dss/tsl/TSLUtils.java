package eu.europa.esig.dss.tsl;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TSLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(TSLUtils.class);
	
	/**
	 * Transforms the provided {@code uri} to the cacheKey used for caching
	 * @param uri {@link String} to decode to the cacheKey
	 * @return {@link String} cache key
	 */
	public static String getCacheKey(String uri) {
		String cacheKey = uri;
		try {
			cacheKey = URLDecoder.decode(uri, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			LOG.debug("Cannot decode the provided uri : [{}]. Reason : [{}]", uri, e.getMessage());
		}
		cacheKey = cacheKey.replaceAll("[^a-zA-Z0-9]+", "_");
		LOG.trace("Return cacheKey [{}] for the given uri [{}]", cacheKey, uri);
		return cacheKey;
	}

}
