package eu.europa.esig.dss.spi.tsl;

import java.util.Date;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;

public interface ValidationInfoRecord extends InfoRecord {
	
	Indication getIndication();
	
	SubIndication getSubIndication();
	
	Date getSigningTime();
	
	CertificateToken getSigningCertificate();
	
	boolean isValid();
	
	boolean isIndeterminate();
	
	boolean isInvalid();

}
