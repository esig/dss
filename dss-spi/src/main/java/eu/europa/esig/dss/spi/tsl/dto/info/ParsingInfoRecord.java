package eu.europa.esig.dss.spi.tsl.dto.info;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.dto.OtherTSLPointer;
import eu.europa.esig.dss.spi.tsl.dto.TrustServiceProvider;

public interface ParsingInfoRecord extends InfoRecord {
	
	public Integer getSequenceNumber();
	
	public Integer getVersion();
	
	public String getTerritory();
	
	public Date getIssueDate();
	
	public Date getNextUpdateDate();
	
	public List<String> getDistributionPoints();
	
	public List<TrustServiceProvider> getTrustServiceProviders();
	
	public List<OtherTSLPointer> getLotlOtherPointers();
	
	public List<OtherTSLPointer> getTlOtherPointers();
	
	public List<String> getPivotUrls();
	
	public String getSigningCertificateAnnouncementUrl();
	
	public List<CertificateToken> getLOTLAnnouncedSigningCertificates();

}
