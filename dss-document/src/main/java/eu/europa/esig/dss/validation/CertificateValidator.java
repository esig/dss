package eu.europa.esig.dss.validation;

import java.util.Date;
import java.util.Objects;

import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.validation.executor.CertificateProcessExecutor;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class CertificateValidator {

	private Date validationTime = new Date();
	private final CertificateToken token;
	private CertificateVerifier certificateVerifier;

	private CertificateValidator(CertificateToken token) {
		Objects.requireNonNull(token, "The certificate is missing");
		this.token = token;
	}

	public static CertificateValidator fromCertificate(final CertificateToken token) {
		return new CertificateValidator(token);
	}

	public void setCertificateVerifier(CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	public void setValidationTime(Date validationTime) {
		this.validationTime = validationTime;
	}

	public CertificateReports validate() {
		final ConstraintsParameters validationPolicyJaxb = ValidationResourceManager.loadPolicyData(null);
		final ValidationPolicy validationPolicy = new EtsiValidationPolicy(validationPolicyJaxb);
		return validate(validationPolicy);
	}

	public CertificateReports validate(ValidationPolicy validationPolicy) {

		SignatureValidationContext svc = new SignatureValidationContext();
		svc.initialize(certificateVerifier);
		svc.addCertificateTokenForVerification(token);
		svc.setCurrentTime(validationTime);
		svc.validate();

		final DiagnosticData diagnosticData = new DiagnosticDataBuilder().usedCertificates(svc.getProcessedCertificates())
				.usedRevocations(svc.getProcessedRevocations()).includeRawRevocationData(certificateVerifier.isIncludeCertificateRevocationValues())
				.certificateSourceTypes(svc.getCertificateSourceTypes())
				.trustedCertificateSource(certificateVerifier.getTrustedCertSource())
				.validationDate(svc.getCurrentTime()).build();

		CertificateProcessExecutor executor = provideProcessExecutorInstance();
		executor.setValidationPolicy(validationPolicy);
		executor.setDiagnosticData(diagnosticData);
		executor.setCertificateId(token.getDSSIdAsString());
		executor.setCurrentTime(svc.getCurrentTime());
		return executor.execute();
	}

	public CertificateProcessExecutor provideProcessExecutorInstance() {
		return new CertificateProcessExecutor();
	}

}
