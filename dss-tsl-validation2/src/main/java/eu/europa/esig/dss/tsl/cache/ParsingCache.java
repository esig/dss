package eu.europa.esig.dss.tsl.cache;

import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.dto.TrustServiceProvider;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingResult;
import eu.europa.esig.dss.tsl.parsing.TLParsingResult;

/**
 * Contains results of TL/LOTL/pivot parsings
 *
 */
public class ParsingCache extends AbstractCache<AbstractParsingResult> {

	private static final Logger LOG = LoggerFactory.getLogger(ParsingCache.class);
	
	/**
	 * Returns a sequence number for an entry with the given key
	 * 
	 * @param cacheKey {@link CacheKey} of the cached entry to get sequence number
	 * @return {@link Integer} sequence number
	 */
	public Integer getSequenceNumber(CacheKey cacheKey) {
		LOG.trace("Extracting a sequence number for the key [{}]...", cacheKey);
		CachedEntry<AbstractParsingResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			AbstractParsingResult cachedResult = cachedEntry.getCachedResult();
			int sequenceNumber = cachedResult.getSequenceNumber();
			LOG.trace("The sequence number of a TL with the key [{}] is [{}]", cacheKey, sequenceNumber);
			return sequenceNumber;
		}
		LOG.debug("The ParsingCache does not contain a parsing result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns a version for an entry with the given key
	 * 
	 * @param cacheKey {@link CacheKey} of the cached entry to get version
	 * @return {@link Integer} version
	 */
	public Integer getVersion(CacheKey cacheKey) {
		LOG.trace("Extracting a version for the key [{}]...", cacheKey);
		CachedEntry<AbstractParsingResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			AbstractParsingResult cachedResult = cachedEntry.getCachedResult();
			int version = cachedResult.getVersion();
			LOG.trace("The version of a TL with the key [{}] is [{}]", cacheKey, version);
			return version;
		}
		LOG.debug("The ParsingCache does not contain a parsing result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns a territory (country) for an entry with the given key
	 * 
	 * @param cacheKey {@link CacheKey} of the cached entry to get territory
	 * @return {@link String} territory
	 */
	public String getTerritory(CacheKey cacheKey) {
		LOG.trace("Extracting a territory for the key [{}]...", cacheKey);
		CachedEntry<AbstractParsingResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			AbstractParsingResult cachedResult = cachedEntry.getCachedResult();
			String territory = cachedResult.getTerritory();
			LOG.trace("The territory of a TL with the key [{}] is [{}]", cacheKey, territory);
			return territory;
		}
		LOG.debug("The ParsingCache does not contain a parsing result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns an issue date for an entry with the given key
	 * 
	 * @param cacheKey {@link CacheKey} of the cached entry to get issue date
	 * @return {@link Date} issue date
	 */
	public Date getIssueDate(CacheKey cacheKey) {
		LOG.trace("Extracting an issue date for the key [{}]...", cacheKey);
		CachedEntry<AbstractParsingResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			AbstractParsingResult cachedResult = cachedEntry.getCachedResult();
			Date issueDate = cachedResult.getIssueDate();
			LOG.trace("The issueDate of a TL with the key [{}] is [{}]", cacheKey, issueDate);
			return issueDate;
		}
		LOG.debug("The ParsingCache does not contain a parsing result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns a next update date for an entry with the given key
	 * 
	 * @param cacheKey {@link CacheKey} of the cached entry to get next update date
	 * @return {@link Date} next update date
	 */
	public Date getNextUpdateDate(CacheKey cacheKey) {
		LOG.trace("Extracting a next update date for the key [{}]...", cacheKey);
		CachedEntry<AbstractParsingResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			AbstractParsingResult cachedResult = cachedEntry.getCachedResult();
			Date nextUpdateDate = cachedResult.getNextUpdateDate();
			LOG.trace("The next update date of a TL with the key [{}] is [{}]", cacheKey, nextUpdateDate);
			return nextUpdateDate;
		}
		LOG.debug("The ParsingCache does not contain a parsing result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns a list of distribution points for an entry with the given key
	 * 
	 * @param cacheKey {@link CacheKey} of the cached entry to get distribution points
	 * @return list of {@link String} distribution points
	 */
	public List<String> getDistributionPoints(CacheKey cacheKey) {
		LOG.trace("Extracting distribution points for the key [{}]...", cacheKey);
		CachedEntry<AbstractParsingResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			AbstractParsingResult cachedResult = cachedEntry.getCachedResult();
			List<String> distributionPoints = cachedResult.getDistributionPoints();
			LOG.trace("The distributionPoints of a TL with the key [{}] are [{}]", cacheKey, distributionPoints);
			return distributionPoints;
		}
		LOG.debug("The ParsingCache does not contain a parsing result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns a list of trust service providers for an entry with the given key
	 * NOTE: applicable only for TL entries! Returns null value for LOTL
	 * 
	 * @param cacheKey {@link CacheKey} of the cached entry to get trust service providers
	 * @return list of {@link TrustServiceProvider}s of TL
	 */
	public List<TrustServiceProvider> getTrustServiceProviders(CacheKey cacheKey) {
		LOG.trace("Extracting TrustServiceProviders for the key [{}]...", cacheKey);
		CachedEntry<AbstractParsingResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			AbstractParsingResult cachedResult = cachedEntry.getCachedResult();
			if (cachedResult instanceof TLParsingResult) {
				List<TrustServiceProvider> trustServiceProviders = ((TLParsingResult) cachedResult).getTrustServiceProviders();
				LOG.trace("The [{}] trustServiceProviders obtained for the key [{}]", trustServiceProviders.size(), cacheKey);
				return trustServiceProviders;
			}
			LOG.warn("Cannot extract trustServiceProviders for an entry with a key [{}]. The parsed file is a LOTL. Return null.");
		}
		LOG.debug("The ParsingCache does not contain a parsing result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns a list of other lotl pointers for an entry with the given key
	 * NOTE: applicable only for LOTL entries! Returns null value for TL
	 * 
	 * @param cacheKey {@link CacheKey} of the cached entry to get other TSL pointers
	 * @return list of {@link OtherTSLPointerDTO}s of LOTL
	 */
	public List<OtherTSLPointerDTO> getLOTLOtherPointers(CacheKey cacheKey) {
		LOG.trace("Extracting other TSL pointers for the key [{}]...", cacheKey);
		CachedEntry<AbstractParsingResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			AbstractParsingResult cachedResult = cachedEntry.getCachedResult();
			if (cachedResult instanceof LOTLParsingResult) {
				List<OtherTSLPointerDTO> otherTSLPointers = ((LOTLParsingResult) cachedResult).getLotlPointers();
				LOG.trace("The otherTSLPointers of a LOTL with the key [{}] are [{}]", cacheKey, otherTSLPointers);
				return otherTSLPointers;
			}
			LOG.warn("Cannot extract otherTSLPointers for an entry with a key [{}]. The parsed file is a TL. Return null.");
		}
		LOG.debug("The ParsingCache does not contain a parsing result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns a list of pivot urls for an entry with the given key
	 * NOTE: applicable only for LOTL entries! Returns null value for TL
	 * 
	 * @param cacheKey {@link CacheKey} of the cached entry to get pivot urls
	 * @return list of {@link String} pivot urls
	 */
	public List<String> getPivotUrls(CacheKey cacheKey) {
		LOG.trace("Extracting containing pivot urls for the key [{}]...", cacheKey);
		CachedEntry<AbstractParsingResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			AbstractParsingResult cachedResult = cachedEntry.getCachedResult();
			if (cachedResult instanceof LOTLParsingResult) {
				List<String> pivotUrls = ((LOTLParsingResult) cachedResult).getPivotURLs();
				LOG.trace("The pivotUrls of a LOTL with the key [{}] are [{}]", cacheKey, pivotUrls);
				return pivotUrls;
			}
			LOG.warn("Cannot extract pivotUrls for an entry with a key [{}]. The parsed file is a TL. Return null.");
		}
		LOG.debug("The ParsingCache does not contain a parsing result for the key [{}]!", cacheKey);
		return null;
	}
	
	@Override
	protected CacheType getCacheType() {
		return CacheType.PARSING;
	}

}
