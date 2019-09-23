package eu.europa.esig.dss.tsl.validation;

import java.util.Date;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.cache.CachedResult;

public class ValidationResult implements CachedResult {
	
	private final Indication indication;
	private final SubIndication subIndication;
	private final Date signingTime;
	private final CertificateToken signingCertificate;

	public ValidationResult(Indication indication, SubIndication subIndication, Date signingTime, CertificateToken signingCertificate) {
		this.indication = indication;
		this.subIndication = subIndication;
		this.signingTime = signingTime;
		this.signingCertificate = signingCertificate;
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

	public boolean isValid() {
		return Indication.TOTAL_PASSED.equals(indication);
	}

	public boolean isIndeterminate() {
		return Indication.INDETERMINATE.equals(indication);
	}

	public boolean isInvalid() {
		return Indication.TOTAL_FAILED.equals(indication);
	}

}
