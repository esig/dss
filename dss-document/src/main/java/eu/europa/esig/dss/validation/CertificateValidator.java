/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation;

import java.util.Date;
import java.util.Objects;

import eu.europa.esig.dss.jaxb.diagnostic.XmlDiagnosticData;
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

		final XmlDiagnosticData diagnosticData = new DiagnosticDataBuilder().usedCertificates(svc.getProcessedCertificates())
				.usedRevocations(svc.getProcessedRevocations()).includeRawCertificateTokens(certificateVerifier.isIncludeCertificateTokenValues())
				.includeRawRevocationData(certificateVerifier.isIncludeCertificateRevocationValues())
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
