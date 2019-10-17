package eu.europa.esig.dss.tsl.validation;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.CachedResult;

public class ValidationResult implements CachedResult {
	
	private final Indication indication;
	private final SubIndication subIndication;
	private final Date signingTime;
	private final CertificateToken signingCertificate;
	private final CertificateSource certificateSource;

	public ValidationResult(Indication indication, SubIndication subIndication, Date signingTime, 
			CertificateToken signingCertificate, CertificateSource certificateSource) {
		this.indication = indication;
		this.subIndication = subIndication;
		this.signingTime = signingTime;
		this.signingCertificate = signingCertificate;
		this.certificateSource = certificateSource;
	}
	
	public Indication getIndication() {
		return indication;
	}

	public SubIndication getSubIndication() {
		return subIndication;
	}

	public Date getSigningTime() {
		return signingTime;
	}

	public CertificateToken getSigningCertificate() {
		return signingCertificate;
	}
	
	public List<CertificateToken> getPotentialSigners() {
		return new ArrayList<CertificateToken>(certificateSource.getCertificates());
	}

}
