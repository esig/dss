package eu.europa.esig.dss.spi.tsl;

import java.io.Serializable;

import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.spi.tsl.dto.info.DownloadInfoRecord;
import eu.europa.esig.dss.spi.tsl.dto.info.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.dto.info.ValidationInfoRecord;
import eu.europa.esig.dss.spi.tsl.identifier.TrustedListIdentifier;

/**
 * Computes summary for a single Trusted List processing result
 *
 */
public class TLInfo implements Serializable {
	
	private static final long serialVersionUID = -1505115221927652721L;

	/**
	 * Address of the source
	 */
	private final String url;
	
	/* DTOs */
	private final DownloadInfoRecord downloadCacheInfo;
	private final ParsingInfoRecord parsingCacheInfo;
	private final ValidationInfoRecord validationCacheInfo;
	
	/**
	 * The default constructor
	 * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
	 * @param parsingCacheInfo {@link ParsingInfoRecord} a parsing cache result
	 * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
	 * @param url {@link String} address used to extract the entry
	 */
	public TLInfo(final DownloadInfoRecord downloadCacheInfo, final ParsingInfoRecord parsingCacheInfo, 
			final ValidationInfoRecord validationCacheInfo, final String url) {
		this.downloadCacheInfo = downloadCacheInfo;
		this.parsingCacheInfo = parsingCacheInfo;
		this.validationCacheInfo = validationCacheInfo;
		this.url = url;
	}
	
	/**
	 * Returns Download Cache Info
	 * @return {@link DownloadInfoRecord}
	 */
	public DownloadInfoRecord getDownloadCacheInfo() {
		return downloadCacheInfo;
	}
	
	/**
	 * Returns Parsing Cache Info
	 * @return {@link ParsingInfoRecord}
	 */
	public ParsingInfoRecord getParsingCacheInfo() {
		return parsingCacheInfo;
	}
	
	/**
	 * Returns Validation Cache Info
	 * @return {@link ValidationInfoRecord}
	 */
	public ValidationInfoRecord getValidationCacheInfo() {
		return validationCacheInfo;
	}
	
	/**
	 * Returns a URL that was used to download the remote file
	 * @return {@link String} url
	 */
	public String getUrl() {
		return url;
	}
	
	/**
	 * Returns the TL id
	 * @return {@link String} id
	 */
	public Identifier getIdentifier() {
		return new TrustedListIdentifier(this);
	}

}
