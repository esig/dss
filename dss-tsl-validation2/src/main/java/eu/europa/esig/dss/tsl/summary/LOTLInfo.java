package eu.europa.esig.dss.tsl.summary;

import java.util.List;

import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;

public class LOTLInfo extends TLInfo {
	
	private static final long serialVersionUID = -8969562861281744320L;

	/**
	 * List of summary for TLs found inside the current LOTL
	 */
	private List<TLInfo> tlInfos;

	/**
	 * List of summary for pivots found inside the current LOTL
	 */
	private List<PivotInfo> pivotInfos;

	/**
	 * The default constructor
	 * @param cacheAccessByKey {@link CacheAccessByKey} a related cache access object
	 * @param url {@link String} address used to extract the entry
	 */
	public LOTLInfo(final CacheAccessByKey cacheAccessByKey, final String url) {
		super(cacheAccessByKey, url);
	}
	
	/**
	 * Returns a list of {@code TLInfo}s summary for TL found in the LOTL
	 * @return list of {@link TLInfo}s
	 */
	public List<TLInfo> getTLInfos() {
		return tlInfos;
	}
	
	/**
	 * Sets a list of {@code TLInfo}s summary for TL found in the LOTL
	 * @param tlInfos list of {@link TLInfo}s
	 */
	public void setTlInfos(List<TLInfo> tlInfos) {
		this.tlInfos = tlInfos;
	}

	/**
	 * Returns a list of {@code PivotInfo}s summary for pivots found in the LOTL
	 * @return list of {@link PivotInfo}s
	 */
	public List<PivotInfo> getPivotInfos() {
		return pivotInfos;
	}

	/**
	 * Sets a list of {@code PivotInfo}s summary for pivots found in the LOTL
	 * @param pivotInfos list of {@link PivotInfo}s
	 */
	public void setPivotInfos(List<PivotInfo> pivotInfos) {
		this.pivotInfos = pivotInfos;
	}
	
	/**
	 * Checks if the current entry is a pivot info
	 * @return TRUE if it is a pivot, FALSE when it is a LOTL
	 */
	public boolean isPivot() {
		return false;
	}

}
