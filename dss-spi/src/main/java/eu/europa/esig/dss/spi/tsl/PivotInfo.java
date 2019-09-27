package eu.europa.esig.dss.spi.tsl;

import eu.europa.esig.dss.spi.tsl.dto.info.DownloadInfoRecord;
import eu.europa.esig.dss.spi.tsl.dto.info.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.dto.info.ValidationInfoRecord;

public class PivotInfo extends LOTLInfo {

	private static final long serialVersionUID = 1724138551018429654L;

	/**
	 * The default constructor
	 * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
	 * @param parsingCacheInfo {@link ParsingInfoRecord} a parsing cache result
	 * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
	 * @param url {@link String} address used to extract the entry
	 */
	public PivotInfo(final DownloadInfoRecord downloadCacheInfo, final ParsingInfoRecord parsingCacheInfo, 
			final ValidationInfoRecord validationCacheInfo, final String url) {
		super(downloadCacheInfo, parsingCacheInfo, validationCacheInfo, url);
	}
	
	@Override
	public boolean isPivot() {
		return true;
	}

}
