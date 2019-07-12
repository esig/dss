package eu.europa.esig.dss.diagnostic;

import java.util.Date;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.enumerations.RevocationReason;

/**
 * Complete revocation wrapper, containing detailed certificate revocation and common information
 */
public class CertificateRevocationWrapper extends RevocationWrapper {
	
	private final XmlCertificateRevocation certificateRevocation;
	
	public CertificateRevocationWrapper(XmlCertificateRevocation certificateRevocation) {
		super(certificateRevocation.getRevocation());
		this.certificateRevocation = certificateRevocation;
	}

	public boolean isStatus() {
		return certificateRevocation.isStatus();
	}

	public RevocationReason getReason() {
		return certificateRevocation.getReason();
	}

	public Date getRevocationDate() {
		return certificateRevocation.getRevocationDate();
	}
	
	public boolean isRevoked() {
		return !isStatus() && getRevocationDate() != null;
	}

}
