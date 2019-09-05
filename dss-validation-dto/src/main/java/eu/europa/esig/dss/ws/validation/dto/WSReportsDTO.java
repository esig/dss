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
package eu.europa.esig.dss.ws.validation.dto;

import java.io.Serializable;

import javax.activation.DataHandler;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlMimeType;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.ws.dto.exception.DSSRemoteServiceException;
import eu.europa.esig.validationreport.ValidationReportFacade;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

@XmlAccessorType(XmlAccessType.FIELD)
@SuppressWarnings("serial")
public class WSReportsDTO implements Serializable {

	@XmlElement(name = "DiagnosticData", namespace = "http://dss.esig.europa.eu/validation/diagnostic")
	private XmlDiagnosticData diagnosticData;

	@XmlElement(name = "SimpleReport", namespace = "http://dss.esig.europa.eu/validation/simple-report")
	private XmlSimpleReport simpleReport;

	@XmlElement(name = "DetailedReport", namespace = "http://dss.esig.europa.eu/validation/detailed-report")
	private XmlDetailedReport detailedReport;

	// Use MTOM to avoid XML ID conflict (between diagnostic data and etsi
	// validation report)
	@XmlMimeType("application/octet-stream")
	private DataHandler validationReportaDataHandler;

	private transient ValidationReportType validationReport;

	public WSReportsDTO() {
	}

	public WSReportsDTO(XmlDiagnosticData diagnosticData, XmlSimpleReport simpleReport, XmlDetailedReport detailedReport) {
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
		this.simpleReport = simpleReport;
	}

	public WSReportsDTO(XmlDiagnosticData diagnosticData, XmlSimpleReport simpleReport, XmlDetailedReport detailedReport,
			ValidationReportType validationReport) {
		this(diagnosticData, simpleReport, detailedReport);
		this.validationReport = validationReport;

		this.validationReportaDataHandler = new DataHandler(new ValidationReportTypeDataSource(validationReport));
	}

	public XmlDiagnosticData getDiagnosticData() {
		return diagnosticData;
	}

	public void setDiagnosticData(XmlDiagnosticData diagnosticData) {
		this.diagnosticData = diagnosticData;
	}

	public XmlSimpleReport getSimpleReport() {
		return simpleReport;
	}

	public void setSimpleReport(XmlSimpleReport simpleReport) {
		this.simpleReport = simpleReport;
	}

	public XmlDetailedReport getDetailedReport() {
		return detailedReport;
	}

	public void setDetailedReport(XmlDetailedReport detailedReport) {
		this.detailedReport = detailedReport;
	}

	public DataHandler getValidationReportaDataHandler() {
		return validationReportaDataHandler;
	}

	public void setValidationReportaDataHandler(DataHandler validationReportaDataHandler) {
		this.validationReportaDataHandler = validationReportaDataHandler;
	}

	public ValidationReportType getValidationReport() {
		if ((validationReport == null) && (validationReportaDataHandler != null)) {
			try {
				validationReport = ValidationReportFacade.newFacade().unmarshall(validationReportaDataHandler.getInputStream());
			} catch (Exception e) {
				throw new DSSRemoteServiceException("Unable to unmarshall ValidationReportType", e);
			}
		}
		return validationReport;
	}

	public void setValidationReport(ValidationReportType validationReport) {
		this.validationReport = validationReport;
	}

}
