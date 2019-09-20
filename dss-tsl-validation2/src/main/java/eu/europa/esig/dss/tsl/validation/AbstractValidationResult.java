package eu.europa.esig.dss.tsl.validation;

import java.util.Date;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.cache.CachedResult;

public abstract class AbstractValidationResult implements CachedResult {
	
	private final Indication indication;
	private final SubIndication subIndication;
	private final Date signingTime;
	private final CertificateToken signingCertificate;
	private final String errorMessage;

	AbstractValidationResult(Indication indication, SubIndication subIndication, Date signingTime, CertificateToken signingCertificate) {
		this.indication = indication;
		this.subIndication = subIndication;
		this.signingTime = signingTime;
		this.signingCertificate = signingCertificate;
		this.errorMessage = null;
	}

	AbstractValidationResult(String errorMessage) {
		this.indication = null;
		this.subIndication = null;
		this.signingTime = null;
		this.signingCertificate = null;
		this.errorMessage = errorMessage;
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

	public String getErrorMessage() {
		return errorMessage;
	}

	public boolean isComplete() {
		return indication != null;
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
