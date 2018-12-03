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
package eu.europa.esig.dss.validation.executor;

import java.util.Date;
import java.util.Objects;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class CertificateProcessExecutor implements ProcessExecutor<CertificateReports> {

	private Date currentTime;
	private ValidationPolicy policy;
	private eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData jaxbDiagnosticData;
	private String certificateId;

	@Override
	public void setCurrentTime(Date currentTime) {
		this.currentTime = currentTime;
	}

	@Override
	public Date getCurrentTime() {
		return currentTime;
	}

	@Override
	public void setDiagnosticData(eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData diagnosticData) {
		this.jaxbDiagnosticData = diagnosticData;
	}

	@Override
	public void setValidationPolicy(ValidationPolicy validationPolicy) {
		this.policy = validationPolicy;
	}

	@Override
	public ValidationPolicy getValidationPolicy() {
		return policy;
	}

	public void setCertificateId(String certificateId) {
		this.certificateId = certificateId;
	}

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
	}

	@Override
	public CertificateReports execute() {

		Objects.requireNonNull(jaxbDiagnosticData, "The diagnostic data is missing");
		Objects.requireNonNull(policy, "The validation policy is missing");
		Objects.requireNonNull(currentTime, "The current time is missing");

		DiagnosticData diagnosticData = new DiagnosticData(jaxbDiagnosticData);

		DetailedReportForCertificateBuilder detailedReportBuilder = new DetailedReportForCertificateBuilder(diagnosticData, policy, currentTime, certificateId);
		DetailedReport detailedReport = detailedReportBuilder.build();

		SimpleReportForCertificateBuilder simpleReportBuilder = new SimpleReportForCertificateBuilder(diagnosticData,
				new eu.europa.esig.dss.validation.reports.DetailedReport(detailedReport), currentTime, certificateId);
		SimpleCertificateReport simpleReport = simpleReportBuilder.build();

		return new CertificateReports(jaxbDiagnosticData, detailedReport, simpleReport);
	}

}
