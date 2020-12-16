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
package eu.europa.esig.dss.validation.executor.certificate;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import eu.europa.esig.dss.validation.executor.AbstractProcessExecutor;
import eu.europa.esig.dss.validation.reports.CertificateReports;

import java.util.Objects;

/**
 * Executes a certificate validation
 */
public class DefaultCertificateProcessExecutor extends AbstractProcessExecutor implements CertificateProcessExecutor {

	/** Id of a certificate to validate */
	private String certificateId;

	@Override
	public void setCertificateId(String certificateId) {
		this.certificateId = certificateId;
	}

	@Override
	public CertificateReports execute() {
		assertConfigurationValid();
		Objects.requireNonNull(certificateId, "The certificate id is missing");

		DiagnosticData diagnosticData = new DiagnosticData(jaxbDiagnosticData);

		DetailedReportForCertificateBuilder detailedReportBuilder = new DetailedReportForCertificateBuilder(
				getI18nProvider(), diagnosticData, policy, currentTime, certificateId);
		XmlDetailedReport detailedReport = detailedReportBuilder.build();

		SimpleReportForCertificateBuilder simpleReportBuilder = new SimpleReportForCertificateBuilder(diagnosticData,
				new eu.europa.esig.dss.detailedreport.DetailedReport(detailedReport), currentTime, certificateId);
		XmlSimpleCertificateReport simpleReport = simpleReportBuilder.build();

		return new CertificateReports(jaxbDiagnosticData, detailedReport, simpleReport);
	}

}
