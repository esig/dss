package eu.europa.esig.dss.spi.tsl.dto.info;

import java.util.Date;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;

public interface ValidationInfoRecord extends InfoRecord {
	
	public Indication getIndication();
	
	public SubIndication getSubIndication();
	
	public Date getSigningTime();
	
	public CertificateToken getSigningCertificate();
	
	public boolean isValid();
	
	public boolean isIndeterminate();
	
	public boolean isInvalid();

}
