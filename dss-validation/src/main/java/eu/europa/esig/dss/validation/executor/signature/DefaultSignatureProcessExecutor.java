/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.executor.signature;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.validation.executor.AbstractProcessExecutor;
import eu.europa.esig.dss.validation.executor.DocumentProcessExecutor;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.util.Objects;

/**
 * This class executes a signature validation process and produces
 * SimpleReport, DetailedReport and ETSI Validation report
 *
 */
public class DefaultSignatureProcessExecutor extends AbstractProcessExecutor implements DocumentProcessExecutor {

	/** The target highest validation level (default: ValidationLevel.ARCHIVAL_DATA) */
	protected ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;

	/** Defines if the ETSI Validation Report shall be generated (default: true) */
	protected boolean enableEtsiValidationReport = true;

	/** Defines if the semantics information shall be included (default: false) */
	protected boolean includeSemantics = false;

	/**
	 * Default constructor instantiating object with default configuration
	 */
	public DefaultSignatureProcessExecutor() {
		// empty
	}

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
		this.validationLevel = validationLevel;
	}

	@Override
	public void setEnableEtsiValidationReport(boolean enableEtsiValidationReport) {
		this.enableEtsiValidationReport = enableEtsiValidationReport;
	}

	@Override
	public void setIncludeSemantics(boolean includeSemantics) {
		this.includeSemantics = includeSemantics;
	}

	@Override
	public Reports execute() {
		assertConfigurationValid();
		Objects.requireNonNull(validationLevel, "The validation level is missing");
		DiagnosticData diagnosticData = getDiagnosticData();
		return buildReports(diagnosticData);
	}

	/**
	 * Gets the DiagnosticDate
	 *
	 * @return {@link DiagnosticData}
	 */
	protected DiagnosticData getDiagnosticData() {
		return new DiagnosticData(jaxbDiagnosticData);
	}

	/**
	 * Builds reports
	 *
	 * @param diagnosticData {@link DiagnosticData} to use
	 * @return {@link Reports}
	 */
	protected Reports buildReports(final DiagnosticData diagnosticData) {

		DetailedReportBuilder detailedReportBuilder = new DetailedReportBuilder(getI18nProvider(), currentTime, policy,
				validationLevel, diagnosticData, includeSemantics);
		XmlDetailedReport jaxbDetailedReport = detailedReportBuilder.build();

		DetailedReport detailedReportWrapper = new DetailedReport(jaxbDetailedReport);

		SimpleReportBuilder simpleReportBuilder = new SimpleReportBuilder(getI18nProvider(), currentTime, policy,
				diagnosticData, detailedReportWrapper, includeSemantics);
		XmlSimpleReport simpleReport = simpleReportBuilder.build();

		ValidationReportType validationReport = null;
		if (enableEtsiValidationReport) {
			ETSIValidationReportBuilder etsiValidationReportBuilder = new ETSIValidationReportBuilder(currentTime,
					diagnosticData, detailedReportWrapper);
			validationReport = etsiValidationReportBuilder.build();
		}

		return new Reports(jaxbDiagnosticData, jaxbDetailedReport, simpleReport, validationReport);
	}

}
