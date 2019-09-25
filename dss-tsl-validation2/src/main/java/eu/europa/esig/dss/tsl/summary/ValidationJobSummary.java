package eu.europa.esig.dss.tsl.summary;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;

/**
 * Computes summary for TLValidationJob
 *
 */
public class ValidationJobSummary {

	private final DownloadCache downloadCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;
	
	/**
	 * List of TLSources to extract summary for
	 */
	private List<TLSource> tlSources;
	
	/**
	 * List of LOTLSource to extract summary for
	 */
	private List<LOTLSource> lotlSources;
	
	/**
	 * The default constructor
	 * @param downloadCache {@link DownloadCache}
	 * @param parsingCache {@link ParsingCache}
	 * @param validationCache {@link ValidationCache}
	 */
	public ValidationJobSummary(final DownloadCache downloadCache, final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.downloadCache = downloadCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}
	
	/**
	 * Sets a list of {@code TLSource}s to get summary for
	 * @param tlSources list of {@link TLSource}s
	 */
	public void setTLSources(List<TLSource> tlSources) {
		this.tlSources = tlSources;
	}

	/**
	 * Sets a list of {@code LOTLSource}s to get summary for
	 * @param lotlSources list of {@link LOTLSource}s
	 */
	public void setLOTLSources(List<LOTLSource> lotlSources) {
		// TODO: map between lotl and pivots ???
		this.lotlSources = lotlSources;
	}
	
	/**
	 * Returns a list of TLInfos for all processed TLs
	 * @return list of {@link TLInfo}s
	 */
	public List<TLInfo> getTLInfos() {
		List<TLInfo> tlInfos = new ArrayList<TLInfo>();
		if (Utils.isCollectionNotEmpty(tlSources)) {
			for (TLSource tlSource : tlSources) {
				tlInfos.add(new TLInfo(tlSource.getCacheKey(), tlSource.getUrl(), downloadCache, parsingCache, validationCache));
			}
		}
		return tlInfos;
	}

	/**
	 * Returns a list of LOTLInfos for all processed LOTLs
	 * @return list of {@link LOTLInfo}s
	 */
	public List<LOTLInfo> getLOTLInfos() {
		List<LOTLInfo> lotlInfos = new ArrayList<LOTLInfo>();
		if (Utils.isCollectionNotEmpty(lotlSources)) {
			for (LOTLSource lotlSource : lotlSources) {
				lotlInfos.add(new LOTLInfo(lotlSource.getCacheKey(), lotlSource.getUrl(), downloadCache, parsingCache, validationCache));
			}
		}
		return lotlInfos;
	}
	
	/**
	 * Returns an amount of processed TLs during the TL Validation job
	 * @return {@code int} number of processed TLs
	 */
	public int getNumberOfProcessedTLs() {
		if (Utils.isCollectionNotEmpty(tlSources)) {
			return tlSources.size();
		}
		return 0;
	}
	
	/**
	 * Returns an amount of processed LOTLs during the TL Validation job
	 * @return {@code int} number of processed LOTLs
	 */
	public int getNumberOfProcessedLOTLs() {
		if (Utils.isCollectionNotEmpty(lotlSources)) {
			return lotlSources.size();
		}
		return 0;
	}

}
