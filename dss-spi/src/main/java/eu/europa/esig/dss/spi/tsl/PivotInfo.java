package eu.europa.esig.dss.spi.tsl;

import java.util.HashMap;
import java.util.Map;

import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.identifier.PivotIdentifier;

public class PivotInfo extends LOTLInfo {

	private static final long serialVersionUID = 1724138551018429654L;
	
	private Map<CertificateToken, CertificatePivotStatus> certificateStatusMap = new HashMap<CertificateToken, CertificatePivotStatus>();

	/**
	 * The default constructor
	 * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
	 * @param parsingCacheInfo {@link ParsingInfoRecord} a parsing cache result
	 * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
	 * @param url {@link String} address used to extract the entry
	 * @param certificates map between {@link CertificateToken} and {@link CertificatePivotStatus}
	 * 					map between certificates and their statuses in the current pivot
	 */
	public PivotInfo(final DownloadInfoRecord downloadCacheInfo, final ParsingInfoRecord parsingCacheInfo, 
			final ValidationInfoRecord validationCacheInfo, final String url, final Map<CertificateToken, CertificatePivotStatus> certificates) {
		super(downloadCacheInfo, parsingCacheInfo, validationCacheInfo, url);
		this.certificateStatusMap = certificates;
	}
	
	/**
	 * Returns a map of certificate tokens with a status regarding to the current pivot
	 * @return map between {@link CertificateToken} and {@link CertificatePivotStatus}
	 */
	public Map<CertificateToken, CertificatePivotStatus> getCertificateStatusMap() {
		return certificateStatusMap;
	}
	
	@Override
	public boolean isPivot() {
		return true;
	}
	
	@Override
	public Identifier getIdentifier() {
		return new PivotIdentifier(this);
	}

}
