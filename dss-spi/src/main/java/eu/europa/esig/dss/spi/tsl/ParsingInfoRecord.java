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
	
}
