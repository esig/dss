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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.validation.executor.CertificateProcessExecutor;
import eu.europa.esig.dss.validation.executor.DefaultCertificateProcessExecutor;
import eu.europa.esig.dss.validation.reports.CertificateReports;

public class CertificateValidator implements ProcessExecutorProvider<CertificateProcessExecutor> {

	private Date validationTime;
	private final CertificateToken token;
	private CertificateVerifier certificateVerifier;
	
	private CertificateProcessExecutor processExecutor;

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
	
	private Date getValidationTime() {
		if (validationTime == null) {
			validationTime = new Date();
		}
		return validationTime;
	}

	public CertificateReports validate() {
		ValidationPolicy defaultPolicy = null;
		try {
			defaultPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		} catch (Exception e) {
			throw new DSSException("Unable to load the default policy", e);
		}
		return validate(defaultPolicy);
	}

	public CertificateReports validate(ValidationPolicy validationPolicy) {

		SignatureValidationContext svc = new SignatureValidationContext();
		svc.initialize(certificateVerifier);
		svc.addCertificateTokenForVerification(token);
		svc.setCurrentTime(getValidationTime());
		svc.validate();

		final XmlDiagnosticData diagnosticData = new DiagnosticDataBuilder().usedCertificates(svc.getProcessedCertificates())
				.usedRevocations(svc.getProcessedRevocations()).includeRawCertificateTokens(certificateVerifier.isIncludeCertificateTokenValues())
				.includeRawRevocationData(certificateVerifier.isIncludeCertificateRevocationValues())
				.certificateSourceTypes(svc.getCertificateSourceTypes())
				.trustedCertificateSource(certificateVerifier.getTrustedCertSource())
				.validationDate(getValidationTime()).build();

		CertificateProcessExecutor executor = provideProcessExecutorInstance();
		executor.setValidationPolicy(validationPolicy);
		executor.setDiagnosticData(diagnosticData);
		executor.setCertificateId(token.getDSSIdAsString());
		executor.setCurrentTime(getValidationTime());
		return executor.execute();
	}

	@Override
	public void setProcessExecutor(CertificateProcessExecutor processExecutor) {
		this.processExecutor = processExecutor;
	}

	public CertificateProcessExecutor provideProcessExecutorInstance() {
		if (processExecutor == null) {
			processExecutor = new DefaultCertificateProcessExecutor();
		}
		return processExecutor;
	}

}
