package eu.europa.esig.dss.spi.tsl.dto.info;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.dto.OtherTSLPointer;
import eu.europa.esig.dss.spi.tsl.dto.TrustServiceProvider;

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
	
	List<CertificateToken> getLOTLAnnouncedSigningCertificates();

}
