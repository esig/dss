package eu.europa.esig.dss.tsl.cache.access;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;

public class DebugCacheAccess {

	private static final Logger LOG = LoggerFactory.getLogger(DebugCacheAccess.class);

	private static final String CARRIAGE_RETURN = "\n";

	/* Global Cache */
	private final DownloadCache downloadCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;

	public DebugCacheAccess(final DownloadCache downloadCache, final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.downloadCache = downloadCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}

	public void dump() {
		StringBuilder sb = new StringBuilder("Cache contents");
		sb.append(CARRIAGE_RETURN);
		sb.append(downloadCache.dump());
		sb.append(CARRIAGE_RETURN);
		sb.append(parsingCache.dump());
		sb.append(CARRIAGE_RETURN);
		sb.append(validationCache.dump());
		LOG.info(sb.toString());
	}

}
