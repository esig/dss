package eu.europa.esig.dss.spi.tsl;

import java.util.Date;
import java.util.List;

public interface ParsingInfoRecord extends InfoRecord {
	
	Integer getSequenceNumber();
	
	Integer getVersion();
	
	String getTerritory();
	
	Date getIssueDate();
	
	Date getNextUpdateDate();
	
	List<String> getDistributionPoints();
	
	List<TrustServiceProvider> getTrustServiceProviders();
	
	List<OtherTSLPointer> getLotlOtherPointers();
	
	List<OtherTSLPointer> getTlOtherPointers();
	
	List<String> getPivotUrls();
	
	String getSigningCertificateAnnouncementUrl();
	
	/**
	 * Returns a number of all {@code TrustServiceProvider}s present in the TL
	 * @return TSP number
	 */
	int getTSPNumber();
	
	/**
	 * Returns a number of all {@code TrustService}s present in the TL
	 * @return TS number
	 */
	int getTSNumber();
	
	/**
	 * Returns a number of all {@code CertificateToken}s present in the TL
	 * @return number of certificates
	 */
	int getCertNumber();
	
}
