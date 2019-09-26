package eu.europa.esig.dss.tsl.cache;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.dto.TrustServiceProvider;

public class ParsingCacheDataAccess extends AbstractCacheDataAccess<ParsingCache> {
	
	public ParsingCacheDataAccess(final ParsingCache parsingCache, final CacheKey cacheKey) {
		super(parsingCache, cacheKey);
	}
	
	public Integer getSequenceNumber() {
		return cache.getSequenceNumber(getCacheKey());
	}
	
	public Integer getVersion() {
		return cache.getVersion(getCacheKey());
	}
	
	public String getTerritory() {
		return cache.getTerritory(getCacheKey());
	}
	
	public Date getIssueDate() {
		return cache.getIssueDate(getCacheKey());
	}
	
	public Date getNextUpdateDate() {
		return cache.getNextUpdateDate(getCacheKey());
	}
	
	public List<String> getDistributionPoints() {
		return cache.getDistributionPoints(getCacheKey());
	}
	
	public List<TrustServiceProvider> getTrustServiceProviders() {
		return cache.getTrustServiceProviders(getCacheKey());
	}
	
	public List<OtherTSLPointerDTO> getLOTLOtherPointers() {
		return cache.getLOTLOtherPointers(getCacheKey());
	}
	
	public List<String> getPivotUrls() {
		return cache.getPivotUrls(getCacheKey());
	}

}
