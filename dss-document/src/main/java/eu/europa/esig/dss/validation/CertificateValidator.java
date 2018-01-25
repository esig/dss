package eu.europa.esig.dss.validation;

import java.util.Date;

import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateValidator {

	private final CertificateToken token;
	private CertificateVerifier certificateVerifier;

	private CertificateValidator(CertificateToken token) {
		this.token = token;
	}

	public static CertificateValidator fromCertificate(final CertificateToken token) {
		return new CertificateValidator(token);
	}

	public void setCertificateVerifier(CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	public Reports validate() {
		SignatureValidationContext svc = new SignatureValidationContext();
		svc.addCertificateTokenForVerification(token);
		svc.setCurrentTime(new Date());
		svc.initialize(certificateVerifier);
		svc.validate();

		DiagnosticDataBuilder builder = new DiagnosticDataBuilder();
		builder.usedCertificates(svc.getProcessedCertificates()).trustedListsCertificateSource(certificateVerifier.getTrustedCertSource())
				.validationDate(svc.getCurrentTime());

		DiagnosticData diagnosticData = builder.build();

		return new Reports(diagnosticData, null, null);

	}

}
