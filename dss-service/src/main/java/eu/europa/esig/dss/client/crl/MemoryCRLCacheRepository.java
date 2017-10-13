package eu.europa.esig.dss.client.crl;

import java.util.concurrent.ConcurrentHashMap;

import eu.europa.esig.dss.crl.CRLValidity;

public class MemoryCRLCacheRepository implements CRLCacheRepository {
	
	private ConcurrentHashMap<String, CRLValidity> cache = new ConcurrentHashMap<>();

	@Override
	public CRLValidity findCrl(String key) {
		return cache.get(key);
	}

	@Override
	public void insertCrl(String key, CRLValidity token) {
		cache.put(key, token);
	}

	@Override
	public void updateCrl(String key, CRLValidity token) {
		cache.put(key, token);
	}

}
