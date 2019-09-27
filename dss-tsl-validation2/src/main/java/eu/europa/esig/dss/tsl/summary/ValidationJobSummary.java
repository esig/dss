package eu.europa.esig.dss.tsl.summary;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.ReadOnlyCacheAccess;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;

/**
 * Computes summary for TLValidationJob
 *
 */
public class ValidationJobSummary {
	
	/**
	 * A read-only access for the cache of the current Validation Job
	 */
	private final ReadOnlyCacheAccess readOnlyCacheAccess;
	
	/**
	 * List of TLSources not linked to any LOTL (manually provided)
	 */
	private final List<TLSource> otherTLSources;
	
	/**
	 * A list of LOTLs with a relationship between their TLs and pivots
	 */
	private final List<LinkedLOTL> linkedLOTLs;
	
	/**
	 * List of LOTL infos for all provided LOTLs
	 */
	private final List<LOTLInfo> lotlInfos;
	
	/**
	 * List of TL infos for otherTLSources
	 */
	private final List<TLInfo> otherTLInfos;
	
	/**
	 * The default constructor
	 */
	public ValidationJobSummary(final ReadOnlyCacheAccess readOnlyCacheAccess, final List<TLSource> otherTLSources, final List<LinkedLOTL> linkedLOTLs) {
		this.readOnlyCacheAccess = readOnlyCacheAccess;
		this.otherTLSources = otherTLSources;
		this.linkedLOTLs = linkedLOTLs;
		this.lotlInfos = buildLOTLInfos();
		this.otherTLInfos = buildOtherTLInfos();
	}

	/**
	 * Returns a list of LOTLInfos for all processed LOTLs
	 * @return list of {@link LOTLInfo}s
	 */
	public List<LOTLInfo> getLOTLInfos() {
		return lotlInfos;
	}
	
	/**
	 * Returns a list of TLInfos for other TLs
	 * @return list of {@link TLInfo}s
	 */
	public List<TLInfo> getOtherTLInfos() {
		return otherTLInfos;
	}
	
	/**
	 * Returns an amount of processed TLs during the TL Validation job
	 * @return {@code int} number of processed TLs
	 */
	public int getNumberOfProcessedTLs() {
		int amount = 0;
		if (Utils.isCollectionNotEmpty(otherTLSources)) {
			amount += otherTLSources.size();
		}
		if (Utils.isCollectionNotEmpty(linkedLOTLs)) {
			for (LinkedLOTL lotl : linkedLOTLs) {
				amount += lotl.getTlSources().size();
			}
		}
		return amount;
	}
	
	/**
	 * Returns an amount of processed LOTLs during the TL Validation job
	 * @return {@code int} number of processed LOTLs
	 */
	public int getNumberOfProcessedLOTLs() {
		if (Utils.isCollectionNotEmpty(linkedLOTLs)) {
			return linkedLOTLs.size();
		}
		return 0;
	}
	
	private List<LOTLInfo> buildLOTLInfos() {
		List<LOTLInfo> lotlInfos = new ArrayList<LOTLInfo>();
		if (Utils.isCollectionNotEmpty(linkedLOTLs)) {
			for (LinkedLOTL lotl : linkedLOTLs) {
				LOTLInfo lotlInfo = buildLOTLInfo(lotl.getLotlSource());
				lotlInfo.setTlInfos(getTLInfos(lotl.getTlSources()));
				lotlInfo.setPivotInfos(getPivotInfos(lotl.getPivots()));
				lotlInfos.add(lotlInfo);
			}
		}
		return lotlInfos;
	}
	
	private LOTLInfo buildLOTLInfo(LOTLSource lotlSource) {
		CacheKey cacheKey = lotlSource.getCacheKey();
		return new LOTLInfo(readOnlyCacheAccess.getDownloadCacheDTO(cacheKey), readOnlyCacheAccess.getParsingCacheDTO(cacheKey), 
				readOnlyCacheAccess.getValidationCacheDTO(cacheKey), lotlSource.getUrl());
	}
	
	private List<PivotInfo> getPivotInfos(List<LOTLSource> pivotSources) {
		List<PivotInfo> pivotInfos = new ArrayList<PivotInfo>();
		if (Utils.isCollectionNotEmpty(pivotSources)) {
			for (LOTLSource pivot : pivotSources) {
				pivotInfos.add(buildPivotInfo(pivot));
			}
		}
		return pivotInfos;
	}
	
	private PivotInfo buildPivotInfo(LOTLSource pivotSource) {
		CacheKey cacheKey = pivotSource.getCacheKey();
		return new PivotInfo(readOnlyCacheAccess.getDownloadCacheDTO(cacheKey), readOnlyCacheAccess.getParsingCacheDTO(cacheKey), 
				readOnlyCacheAccess.getValidationCacheDTO(cacheKey), pivotSource.getUrl());
	}
	
	private List<TLInfo> buildOtherTLInfos() {
		return getTLInfos(otherTLSources);
	}
	
	private List<TLInfo> getTLInfos(List<TLSource> tlSources) {
		List<TLInfo> tlInfos = new ArrayList<TLInfo>();
		if (Utils.isCollectionNotEmpty(tlSources)) {
			for (TLSource tlSource : tlSources) {
				tlInfos.add(buildTLInfo(tlSource));
			}
		}
		return tlInfos;
	}
	
	private TLInfo buildTLInfo(TLSource tlSource) {
		CacheKey cacheKey = tlSource.getCacheKey();
		return new TLInfo(readOnlyCacheAccess.getDownloadCacheDTO(cacheKey), readOnlyCacheAccess.getParsingCacheDTO(cacheKey), 
				readOnlyCacheAccess.getValidationCacheDTO(cacheKey), tlSource.getUrl());
	}

}
