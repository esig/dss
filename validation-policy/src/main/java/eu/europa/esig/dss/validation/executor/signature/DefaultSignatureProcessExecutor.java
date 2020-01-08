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
package eu.europa.esig.dss.validation.executor.signature;

import java.util.Date;
import java.util.Objects;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.validation.executor.AbstractProcessExecutor;
import eu.europa.esig.dss.validation.executor.SignatureProcessExecutor;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

/**
 * This class executes a signature validation process and produces
 * SimpleReport, DetailedReport and ETSI Validation report
 *
 */
public class DefaultSignatureProcessExecutor extends AbstractProcessExecutor implements SignatureProcessExecutor {

	protected ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;
	protected boolean enableEtsiValidationReport = true;

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
		this.validationLevel = validationLevel;
	}

	@Override
	public void setEnableEtsiValidationReport(boolean enableEtsiValidationReport) {
		this.enableEtsiValidationReport = enableEtsiValidationReport;
	}
	
	@Override
	public Reports execute() {
		assertConfigurationValid();
		Objects.requireNonNull(validationLevel, "The validation level is missing");
		DiagnosticData diagnosticData = getDiagnosticData();
		return buildReports(diagnosticData, getCurrentTime());
	}
	
	protected DiagnosticData getDiagnosticData() {
		return new DiagnosticData(jaxbDiagnosticData);
	}
	
	protected Reports buildReports(final DiagnosticData diagnosticData, final Date validationTime) {
		
		DetailedReportBuilder detailedReportBuilder = new DetailedReportBuilder(getI18nProvider(), currentTime, policy, validationLevel, diagnosticData);
		XmlDetailedReport jaxbDetailedReport = detailedReportBuilder.build();

		DetailedReport detailedReportWrapper = new DetailedReport(jaxbDetailedReport);

		SimpleReportBuilder simpleReportBuilder = new SimpleReportBuilder(currentTime, policy, diagnosticData, detailedReportWrapper);
		XmlSimpleReport simpleReport = simpleReportBuilder.build();

		ValidationReportType validationReport = null;
		if (enableEtsiValidationReport) {
			ETSIValidationReportBuilder etsiValidationReportBuilder = new ETSIValidationReportBuilder(currentTime, diagnosticData,
					detailedReportWrapper);
			validationReport = etsiValidationReportBuilder.build();
		}

		return new Reports(jaxbDiagnosticData, jaxbDetailedReport, simpleReport, validationReport);
	}

}
