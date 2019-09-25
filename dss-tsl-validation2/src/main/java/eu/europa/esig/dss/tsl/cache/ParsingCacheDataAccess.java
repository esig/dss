package eu.europa.esig.dss.tsl.cache;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.dto.TrustServiceProvider;

public class ParsingCacheDataAccess extends AbstractCacheDataAccess<ParsingCache> {
	
	public ParsingCacheDataAccess(ParsingCache parsingCache) {
		super(parsingCache);
	}
	
	public Integer getSequenceNumber(CacheKey cacheKey) {
		return cache.getSequenceNumber(cacheKey);
	}
	
	public Integer getVersion(CacheKey cacheKey) {
		return cache.getVersion(cacheKey);
	}
	
	public String getTerritory(CacheKey cacheKey) {
		return cache.getTerritory(cacheKey);
	}
	
	public Date getIssueDate(CacheKey cacheKey) {
		return cache.getIssueDate(cacheKey);
	}
	
	public Date getNextUpdateDate(CacheKey cacheKey) {
		return cache.getNextUpdateDate(cacheKey);
	}
	
	public List<String> getDistributionPoints(CacheKey cacheKey) {
		return cache.getDistributionPoints(cacheKey);
	}
	
	public List<TrustServiceProvider> getTrustServiceProviders(CacheKey cacheKey) {
		return cache.getTrustServiceProviders(cacheKey);
	}
	
	public List<OtherTSLPointerDTO> getLOTLOtherPointers(CacheKey cacheKey) {
		return cache.getLOTLOtherPointers(cacheKey);
	}
	
	public List<String> getPivotUrls(CacheKey cacheKey) {
		return cache.getPivotUrls(cacheKey);
	}

}
