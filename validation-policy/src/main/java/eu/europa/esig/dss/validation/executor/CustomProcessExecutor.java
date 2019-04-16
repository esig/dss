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

import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;

public class CustomProcessExecutor implements ProcessExecutor<Reports> {

	private Date currentTime = new Date();
	private ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;

	private eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData jaxbDiagnosticData;

	private ValidationPolicy policy;

	@Override
	public void setCurrentTime(Date currentTime) {
		this.currentTime = currentTime;
	}

	@Override
	public void setDiagnosticData(eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData diagnosticData) {
		this.jaxbDiagnosticData = diagnosticData;
	}

	@Override
	public void setValidationPolicy(ValidationPolicy policy) {
		this.policy = policy;
	}

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
		this.validationLevel = validationLevel;
	}

	@Override
	public Reports execute() {

		Objects.requireNonNull(jaxbDiagnosticData, "The diagnostic data is missing");
		Objects.requireNonNull(policy, "The validation policy is missing");
		Objects.requireNonNull(currentTime, "The current time is missing");
		Objects.requireNonNull(validationLevel, "The validation level is missing");

		DiagnosticData diagnosticData = new DiagnosticData(jaxbDiagnosticData);

		DetailedReportBuilder detailedReportBuilder = new DetailedReportBuilder(currentTime, policy, validationLevel, diagnosticData);
		eu.europa.esig.dss.jaxb.detailedreport.DetailedReport jaxbDetailedReport = detailedReportBuilder.build();

		DetailedReport detailedReportWrapper = new DetailedReport(jaxbDetailedReport);

		SimpleReportBuilder simpleReportBuilder = new SimpleReportBuilder(currentTime, policy, diagnosticData, detailedReportWrapper);
		SimpleReport simpleReport = simpleReportBuilder.build();
		
		ETSIValidationReportBuilder etsiValidationReportBuilder = new ETSIValidationReportBuilder(currentTime, policy, diagnosticData, detailedReportWrapper);
		ValidationReportType validationReport = etsiValidationReportBuilder.build();

		return new Reports(jaxbDiagnosticData, jaxbDetailedReport, simpleReport, validationReport);
	}

	@Override
	public Date getCurrentTime() {
		return currentTime;
	}

	@Override
	public ValidationPolicy getValidationPolicy() {
		return policy;
	}

}
