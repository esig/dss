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
package eu.europa.esig.dss.validation.reports.dto;

import java.io.Serializable;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;

public class ReportsDTO implements Serializable {

	private static final long serialVersionUID = -6854645201561656069L;

	private DiagnosticData diagnosticData;
	private SimpleReport simpleReport;
	private DetailedReport detailedReport;
	private ValidationReportType validationReport;

	public ReportsDTO() {
	}

	public ReportsDTO(DiagnosticData diagnosticData, SimpleReport simpleReport, DetailedReport detailedReport, 
			ValidationReportType validationReport) {
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
		this.simpleReport = simpleReport;
		this.validationReport = validationReport;
	}

	public DiagnosticData getDiagnosticData() {
		return diagnosticData;
	}

	public void setDiagnosticData(DiagnosticData diagnosticData) {
		this.diagnosticData = diagnosticData;
	}

	public SimpleReport getSimpleReport() {
		return simpleReport;
	}

	public void setSimpleReport(SimpleReport simpleReport) {
		this.simpleReport = simpleReport;
	}

	public eu.europa.esig.dss.jaxb.detailedreport.DetailedReport getDetailedReport() {
		return detailedReport;
	}

	public void setDetailedReport(eu.europa.esig.dss.jaxb.detailedreport.DetailedReport detailedReport) {
		this.detailedReport = detailedReport;
	}
	
	public ValidationReportType getEtsiValidationReport() {
		return validationReport;
	}
	
	public void setEtsiValidationReport(ValidationReportType validationReport) {
		this.validationReport = validationReport;
	}
	
}
