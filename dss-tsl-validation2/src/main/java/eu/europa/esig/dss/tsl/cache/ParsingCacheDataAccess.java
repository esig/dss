package eu.europa.esig.dss.tsl.cache;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.tsl.cache.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.dto.TrustServiceProvider;

public class ParsingCacheDataAccess extends AbstractCacheDataAccess<ParsingCache> {
	
	public ParsingCacheDataAccess(final ParsingCache parsingCache, final CacheKey cacheKey) {
		super(parsingCache, cacheKey);
	}
	
	@Override
	public ParsingCacheDTO getCacheDTO() {
		ParsingCacheDTO parsingCacheDTO = new ParsingCacheDTO(super.getCacheDTO());
		parsingCacheDTO.setSequenceNumber(getSequenceNumber());
		parsingCacheDTO.setVersion(getVersion());
		parsingCacheDTO.setTerritory(getTerritory());
		parsingCacheDTO.setIssueDate(getIssueDate());
		parsingCacheDTO.setNextUpdateDate(getNextUpdateDate());
		parsingCacheDTO.setDistributionPoints(getDistributionPoints());
		parsingCacheDTO.setTrustServiceProviders(getTrustServiceProviders());
		parsingCacheDTO.setLotlOtherPointers(getLOTLOtherPointers());
		parsingCacheDTO.setPivotUrls(getPivotUrls());
		return parsingCacheDTO;
	}
	
	private Integer getSequenceNumber() {
		return cache.getSequenceNumber(getCacheKey());
	}
	
	private Integer getVersion() {
		return cache.getVersion(getCacheKey());
	}
	
	private String getTerritory() {
		return cache.getTerritory(getCacheKey());
	}
	
	private Date getIssueDate() {
		return cache.getIssueDate(getCacheKey());
	}
	
	private Date getNextUpdateDate() {
		return cache.getNextUpdateDate(getCacheKey());
	}
	
	private List<String> getDistributionPoints() {
		return cache.getDistributionPoints(getCacheKey());
	}
	
	private List<TrustServiceProvider> getTrustServiceProviders() {
		return cache.getTrustServiceProviders(getCacheKey());
	}
	
	private List<OtherTSLPointerDTO> getLOTLOtherPointers() {
		return cache.getLOTLOtherPointers(getCacheKey());
	}
	
	private List<String> getPivotUrls() {
		return cache.getPivotUrls(getCacheKey());
	}

}
