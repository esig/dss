package eu.europa.esig.dss.tsl.dto;

import java.util.Date;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.dto.info.ValidationInfoRecord;

public class ValidationCacheDTO extends AbstractCacheDTO implements ValidationInfoRecord {

	private static final long serialVersionUID = -4534009898186648431L;
	
	private Indication indication;
	private SubIndication subIndication;
	private Date signingTime;
	private CertificateToken signingCertificate;

	public ValidationCacheDTO() {}
	
	public ValidationCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}
	
	@Override
	public Indication getIndication() {
		return indication;
	}
	
	public void setIndication(Indication indication) {
		this.indication = indication;
	}

	@Override
	public SubIndication getSubIndication() {
		return subIndication;
	}
	
	public void setSubIndication(SubIndication subIndication) {
		this.subIndication = subIndication;
	}

	@Override
	public Date getSigningTime() {
		return signingTime;
	}
	
	public void setSigningTime(Date signingTime) {
		this.signingTime = signingTime;
	}

	@Override
	public CertificateToken getSigningCertificate() {
		return signingCertificate;
	}

	public void setSigningCertificate(CertificateToken signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	@Override
	public boolean isValid() {
		return Indication.TOTAL_PASSED.equals(indication);
	}

	@Override
	public boolean isIndeterminate() {
		return Indication.INDETERMINATE.equals(indication);
	}

	@Override
	public boolean isInvalid() {
		return Indication.TOTAL_FAILED.equals(indication);
	}

}
