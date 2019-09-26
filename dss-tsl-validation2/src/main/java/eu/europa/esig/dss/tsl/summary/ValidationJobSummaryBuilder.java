package eu.europa.esig.dss.tsl.summary;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.CacheAccessFactory;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.ReadOnlyCacheAccess;
import eu.europa.esig.dss.tsl.job.TLSourceBuilder;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.utils.TLValidationUtils;
import eu.europa.esig.dss.utils.Utils;

public class ValidationJobSummaryBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationJobSummaryBuilder.class);
	
	/**
	 * A factory to access the cache of the current Validation Job
	 */
	private final CacheAccessFactory cacheAccessFactory;
	
	/**
	 * List of TLSources to extract summary for
	 */
	private final TLSource[] tlSources;
	
	/**
	 * List of LOTLSource to extract summary for
	 */
	private final LOTLSource[] lotlSources;
	
	public ValidationJobSummaryBuilder(final CacheAccessFactory cacheAccessFactory, final TLSource[] tlSources, final LOTLSource[] lotlSources) {
		this.cacheAccessFactory = cacheAccessFactory;
		this.tlSources = tlSources;
		this.lotlSources = lotlSources;
	}
	
	public ValidationJobSummary build() {
		final List<TLSource> tlList = new ArrayList<TLSource>();
		if (Utils.isArrayNotEmpty(tlSources)) {
			tlList.addAll(Arrays.asList(tlSources));
		}
		final List<LOTLSource> lotlList = new ArrayList<LOTLSource>();
		if (Utils.isArrayNotEmpty(lotlSources)) {
			lotlList.addAll(Arrays.asList(lotlSources));
			final ReadOnlyCacheAccess readOnlyCacheAccess = cacheAccessFactory.getReadOnlyCacheAccess();
			Map<CacheKey, AbstractParsingResult> parsingResultMap = readOnlyCacheAccess.getParsingResultMap(TLValidationUtils.getCacheKeyList(lotlList));
			TLSourceBuilder tlSourceBuilder = new TLSourceBuilder(lotlList, parsingResultMap);
			tlList.addAll(tlSourceBuilder.build());
		}
		LOG.info("Building a validation job summary for {} LOTLs and {} TLs...", lotlList.size(), tlList.size());
		return new ValidationJobSummary(cacheAccessFactory, tlList, lotlList);
	}

}
