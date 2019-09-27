package eu.europa.esig.dss.tsl.summary;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.tsl.dto.OtherTSLPointer;
import eu.europa.esig.dss.tsl.cache.ReadOnlyCacheAccess;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;

public class ValidationJobSummaryBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationJobSummaryBuilder.class);
	
	/**
	 * A read-only access for the cache of the current Validation Job
	 */
	private final ReadOnlyCacheAccess readOnlyCacheAccess;
	
	/**
	 * List of TLSources to extract summary for
	 */
	private final TLSource[] tlSources;
	
	/**
	 * List of LOTLSource to extract summary for
	 */
	private final LOTLSource[] lotlSources;
	
	public ValidationJobSummaryBuilder(final ReadOnlyCacheAccess readOnlyCacheAccess, final TLSource[] tlSources, final LOTLSource[] lotlSources) {
		this.readOnlyCacheAccess = readOnlyCacheAccess;
		this.tlSources = tlSources;
		this.lotlSources = lotlSources;
	}
	
	public ValidationJobSummary build() {
		int tlAmount = 0;
				
		final List<TLSource> tlList = new ArrayList<TLSource>();
		if (Utils.isArrayNotEmpty(tlSources)) {
			tlList.addAll(Arrays.asList(tlSources));
			tlAmount += tlSources.length;
		}
		
		final List<LinkedLOTL> lotlList = new ArrayList<LinkedLOTL>();
		if (Utils.isArrayNotEmpty(lotlSources)) {
			
			for (LOTLSource lotl : lotlSources) {
				ParsingCacheDTO lotlParsingResult = readOnlyCacheAccess.getParsingCacheDTO(lotl.getCacheKey());
				List<TLSource> lotlTLSources = extractTLSources(lotlParsingResult);
				tlAmount += lotlTLSources.size();
				
				LinkedLOTL linkedLOTL;
				if (lotl.isPivotSupport()) {
					List<LOTLSource> pivotSources = extractPivotSources(lotlParsingResult);
					linkedLOTL = new LinkedLOTL(lotl, lotlTLSources, pivotSources);
				} else {
					linkedLOTL = new LinkedLOTL(lotl, lotlTLSources);
				}
				lotlList.add(linkedLOTL);
				
			}
		}
		
		LOG.info("Building a validation job summary for {} LOTLs and {} TLs...", lotlList.size(), tlAmount);
		return new ValidationJobSummary(readOnlyCacheAccess, tlList, lotlList);
	}
	
	private List<TLSource> extractTLSources(ParsingCacheDTO lotlParsingResult) {
		List<TLSource> result = new ArrayList<TLSource>();
		List<OtherTSLPointer> tlPointers = lotlParsingResult.getTlOtherPointers();
		for (OtherTSLPointer otherTSLPointerDTO : tlPointers) {
			TLSource tlSource = new TLSource(otherTSLPointerDTO.getLocation());
			result.add(tlSource);
		}
		return result;
	}
	
	private List<LOTLSource> extractPivotSources(ParsingCacheDTO lotlParsingResult) {
		List<LOTLSource> result = new ArrayList<LOTLSource>();
		List<String> pivotUrls = lotlParsingResult.getPivotUrls();
		for (String pivotUrl : pivotUrls) {
			LOTLSource pivotSource = new LOTLSource(pivotUrl);
			result.add(pivotSource);
		}
		return result;
	}

}
