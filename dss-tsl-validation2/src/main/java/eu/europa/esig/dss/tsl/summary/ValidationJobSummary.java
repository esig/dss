package eu.europa.esig.dss.tsl.summary;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.cache.CacheAccessFactory;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;

/**
 * Computes summary for TLValidationJob
 *
 */
public class ValidationJobSummary {
	
	/**
	 * A factory to access the cache of the current Validation Job
	 */
	private final CacheAccessFactory cacheAccessFactory;
	
	/**
	 * List of TLSources not linked to any LOTL (manually provided)
	 */
	private final List<TLSource> otherTLSources;
	
	/**
	 * A list of LOTLs with a relationship between their TLs and pivots
	 */
	private final List<LinkedLOTL> linkedLOTLs;
	
	/**
	 * The default constructor
	 */
	public ValidationJobSummary(final CacheAccessFactory cacheAccessFactory, final List<TLSource> otherTLSources, final List<LinkedLOTL> linkedLOTLs) {
		this.cacheAccessFactory = cacheAccessFactory;
		this.otherTLSources = otherTLSources;
		this.linkedLOTLs = linkedLOTLs;
	}

	/**
	 * Returns a list of LOTLInfos for all processed LOTLs
	 * @return list of {@link LOTLInfo}s
	 */
	public List<LOTLInfo> getLOTLInfos() {
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
		CacheAccessByKey cacheAccess = cacheAccessFactory.getCacheAccess(lotlSource.getCacheKey());
		return new LOTLInfo(cacheAccess.getDownloadReadOnlyResult(), cacheAccess.getParsingReadOnlyResult(), 
				cacheAccess.getValidationReadOnlyResult(), lotlSource.getUrl());
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
		CacheAccessByKey cacheAccess = cacheAccessFactory.getCacheAccess(pivotSource.getCacheKey());
		return new PivotInfo(cacheAccess.getDownloadReadOnlyResult(), cacheAccess.getParsingReadOnlyResult(), 
				cacheAccess.getValidationReadOnlyResult(), pivotSource.getUrl());
	}
	
	/**
	 * Returns a list of TLInfos for other TLs
	 * @return list of {@link TLInfo}s
	 */
	public List<TLInfo> getOtherTLInfos() {
		return getTLInfos(otherTLSources);
	}
	
	private List<TLInfo> getTLInfos(List<TLSource> tlSources) {
		List<TLInfo> tlInfos = new ArrayList<TLInfo>();
		if (Utils.isCollectionNotEmpty(tlSources)) {
			for (TLSource tlSource : tlSources) {
				tlInfos.add(buildPivotInfo(tlSource));
			}
		}
		return tlInfos;
	}
	
	private TLInfo buildPivotInfo(TLSource tlSource) {
		CacheAccessByKey cacheAccess = cacheAccessFactory.getCacheAccess(tlSource.getCacheKey());
		return new TLInfo(cacheAccess.getDownloadReadOnlyResult(), cacheAccess.getParsingReadOnlyResult(), 
				cacheAccess.getValidationReadOnlyResult(), tlSource.getUrl());
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

}
