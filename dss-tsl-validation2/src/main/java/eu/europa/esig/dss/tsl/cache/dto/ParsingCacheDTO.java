package eu.europa.esig.dss.tsl.cache.dto;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.dto.TrustServiceProvider;
import eu.europa.esig.dss.tsl.utils.TLValidationUtils;

public class ParsingCacheDTO extends AbstractCacheDTO {
	
	private static final long serialVersionUID = 5464908480606825440L;
	
	private Integer sequenceNumber;
	private Integer version;
	private String territory;
	private Date issueDate;
	private Date nextUpdateDate;
	private List<String> distributionPoints;
	private List<TrustServiceProvider> trustServiceProviders;
	private List<OtherTSLPointerDTO> lotlOtherPointers;
	private List<OtherTSLPointerDTO> tlOtherPointers;
	private List<String> pivotUrls;

	public ParsingCacheDTO() {}
	
	public ParsingCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}
	
	public Integer getSequenceNumber() {
		return sequenceNumber;
	}

	public void setSequenceNumber(Integer sequenceNumber) {
		this.sequenceNumber = sequenceNumber;
	}
	
	public Integer getVersion() {
		return version;
	}
	
	public void setVersion(Integer version) {
		this.version = version;
	}
	
	public String getTerritory() {
		return territory;
	}
	
	public void setTerritory(String territory) {
		this.territory = territory;
	}
	
	public Date getIssueDate() {
		return issueDate;
	}
	
	public void setIssueDate(Date issueDate) {
		this.issueDate = issueDate;
	}
	
	public Date getNextUpdateDate() {
		return nextUpdateDate;
	}
	
	public void setNextUpdateDate(Date nextUpdateDate) {
		this.nextUpdateDate = nextUpdateDate;
	}
	
	public List<String> getDistributionPoints() {
		return distributionPoints;
	}
	
	public void setDistributionPoints(List<String> distributionPoints) {
		this.distributionPoints = distributionPoints;
	}
	
	public List<TrustServiceProvider> getTrustServiceProviders() {
		return trustServiceProviders;
	}
	
	public void setTrustServiceProviders(List<TrustServiceProvider> trustServiceProviders) {
		this.trustServiceProviders = trustServiceProviders;
	}
	
	public List<OtherTSLPointerDTO> getLotlOtherPointers() {
		return lotlOtherPointers;
	}
	
	public void setLotlOtherPointers(List<OtherTSLPointerDTO> lotlOtherPointers) {
		this.lotlOtherPointers = lotlOtherPointers;
	}
	
	public List<OtherTSLPointerDTO> getTlOtherPointers() {
		return tlOtherPointers;
	}
	
	public void setTlOtherPointers(List<OtherTSLPointerDTO> tlOtherPointers) {
		this.tlOtherPointers = tlOtherPointers;
	}
	
	public List<String> getPivotUrls() {
		return pivotUrls;
	}

	public void setPivotUrls(List<String> pivotUrls) {
		this.pivotUrls = pivotUrls;
	}

	public List<CertificateToken> getLOTLAnnouncedSigningCertificates() {
		return TLValidationUtils.getLOTLAnnouncedSigningCertificates(getLotlOtherPointers());
	}

}
