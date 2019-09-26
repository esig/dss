package eu.europa.esig.dss.tsl.summary;

import java.util.ArrayList;
import java.util.List;

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
	private final List<TLSource> orphanTLSources;
	
	/**
	 * A list of LOTLs with a relationship between their TLs and pivots
	 */
	private final List<LinkedLOTL> linkedLOTLs;
	
	/**
	 * The default constructor
	 */
	public ValidationJobSummary(final CacheAccessFactory cacheAccessFactory, final List<TLSource> orphanTLSources, final List<LinkedLOTL> linkedLOTLs) {
		this.cacheAccessFactory = cacheAccessFactory;
		this.orphanTLSources = orphanTLSources;
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
				LOTLInfo lotlInfo = new LOTLInfo(cacheAccessFactory.getCacheAccess(lotl.getLotlSource().getCacheKey()), lotl.getLotlSource().getUrl());
				lotlInfo.setTlInfos(getTLInfos(lotl.getTlSources()));
				lotlInfo.setPivotInfos(getPivotInfos(lotl.getPivots()));
				lotlInfos.add(lotlInfo);
			}
		}
		return lotlInfos;
	}
	
	private List<PivotInfo> getPivotInfos(List<LOTLSource> pivotSources) {
		List<PivotInfo> pivotInfos = new ArrayList<PivotInfo>();
		if (Utils.isCollectionNotEmpty(pivotSources)) {
			for (TLSource pivot : pivotSources) {
				pivotInfos.add(new PivotInfo(cacheAccessFactory.getCacheAccess(pivot.getCacheKey()), pivot.getUrl()));
			}
		}
		return pivotInfos;
	}
	
	/**
	 * Returns a list of TLInfos for orphan TLs
	 * @return list of {@link TLInfo}s
	 */
	public List<TLInfo> getOrphanTLInfos() {
		return getTLInfos(orphanTLSources);
	}
	
	private List<TLInfo> getTLInfos(List<TLSource> tlSources) {
		List<TLInfo> tlInfos = new ArrayList<TLInfo>();
		if (Utils.isCollectionNotEmpty(tlSources)) {
			for (TLSource tlSource : tlSources) {
				tlInfos.add(new TLInfo(cacheAccessFactory.getCacheAccess(tlSource.getCacheKey()), tlSource.getUrl()));
			}
		}
		return tlInfos;
	}
	
	/**
	 * Returns an amount of processed TLs during the TL Validation job
	 * @return {@code int} number of processed TLs
	 */
	public int getNumberOfProcessedTLs() {
		int amount = 0;
		if (Utils.isCollectionNotEmpty(orphanTLSources)) {
			amount += orphanTLSources.size();
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
