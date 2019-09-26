package eu.europa.esig.dss.tsl.summary;

import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;

public class PivotInfo extends LOTLInfo {

	private static final long serialVersionUID = 1724138551018429654L;

	public PivotInfo(CacheAccessByKey cacheAccessByKey, String url) {
		super(cacheAccessByKey, url);
	}
	
	@Override
	public boolean isPivot() {
		return true;
	}

}
