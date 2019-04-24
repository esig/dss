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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;

@XmlRootElement(name = "WSReportsDTO", namespace = "http://validation.dss.esig.europa.eu/")
@XmlAccessorType(XmlAccessType.FIELD)
public class WSReportsDTO {

	@XmlElement(namespace = "http://dss.esig.europa.eu/validation/diagnostic")
	private DiagnosticData diagnosticData;

	@XmlElement(namespace = "http://dss.esig.europa.eu/validation/simple-report")
	private SimpleReport simpleReport;

	@XmlElement(namespace = "http://dss.esig.europa.eu/validation/detailed-report")
	private DetailedReport detailedReport;

	@XmlElement(namespace = "http://uri.etsi.org/19102/v1.2.1")
	private ValidationReportType etsiValidationReport;

	public WSReportsDTO() {
	}

	public WSReportsDTO(DiagnosticData diagnosticData, SimpleReport simpleReport, DetailedReport detailedReport, 
			ValidationReportType validationReport) {
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
		this.simpleReport = simpleReport;
		this.etsiValidationReport = validationReport;
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
		return etsiValidationReport;
	}
	
	public void setEtsiValidationReport(ValidationReportType validationReport) {
		this.etsiValidationReport = validationReport;
	}

}
