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

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.ws.dto.exception.DSSRemoteServiceException;
import eu.europa.esig.validationreport.ValidationReportFacade;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import javax.activation.DataHandler;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlMimeType;
import java.io.Serializable;

/**
 * Represents a validation response DTO, containing the reports
 */
@XmlAccessorType(XmlAccessType.FIELD)
@SuppressWarnings("serial")
public class WSReportsDTO implements Serializable {

	/** The DiagnosticData report */
	@XmlElement(name = "DiagnosticData", namespace = "http://dss.esig.europa.eu/validation/diagnostic")
	private XmlDiagnosticData diagnosticData;

	/** The SimpleReport report */
	@XmlElement(name = "SimpleReport", namespace = "http://dss.esig.europa.eu/validation/simple-report")
	private XmlSimpleReport simpleReport;

	/** The DetailedReport report */
	@XmlElement(name = "DetailedReport", namespace = "http://dss.esig.europa.eu/validation/detailed-report")
	private XmlDetailedReport detailedReport;

	// Use MTOM to avoid XML ID conflict (between diagnostic data and etsi
	// validation report)
	/** Uses MTOM to avoid XML ID conflict (between diagnostic data and etsi validation report) */
	@XmlMimeType("application/octet-stream")
	private transient DataHandler validationReportDataHandler;

	/** The ETSI validation report */
	private transient ValidationReportType validationReport;

	/**
	 * Empty constructor
	 */
	public WSReportsDTO() {
	}

	/**
	 * Default constructor without ETSI Validation report
	 *
	 * @param diagnosticData {@link XmlDiagnosticData}
	 * @param simpleReport {@link XmlSimpleReport}
	 * @param detailedReport {@link XmlDetailedReport}
	 */
	public WSReportsDTO(XmlDiagnosticData diagnosticData, XmlSimpleReport simpleReport, XmlDetailedReport detailedReport) {
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
		this.simpleReport = simpleReport;
	}

	/**
	 * Default constructor with ETSI Validation report
	 *
	 * @param diagnosticData {@link XmlDiagnosticData}
	 * @param simpleReport {@link XmlSimpleReport}
	 * @param detailedReport {@link XmlDetailedReport}
	 * @param validationReport {@link ValidationReportType}
	 */
	public WSReportsDTO(XmlDiagnosticData diagnosticData, XmlSimpleReport simpleReport, XmlDetailedReport detailedReport,
			ValidationReportType validationReport) {
		this(diagnosticData, simpleReport, detailedReport);
		this.validationReport = validationReport;

		this.validationReportDataHandler = new DataHandler(new ValidationReportTypeDataSource(validationReport));
	}

	/**
	 * Gets the DiagnosticData
	 *
	 * @return {@link XmlDiagnosticData}
	 */
	public XmlDiagnosticData getDiagnosticData() {
		return diagnosticData;
	}

	/**
	 * Sets the DiagnosticData
	 *
	 * @param diagnosticData {@link XmlDiagnosticData}
	 */
	public void setDiagnosticData(XmlDiagnosticData diagnosticData) {
		this.diagnosticData = diagnosticData;
	}

	/**
	 * Gets a SimpleReport
	 *
	 * @return {@link XmlSimpleReport}
	 */
	public XmlSimpleReport getSimpleReport() {
		return simpleReport;
	}

	/**
	 * Sets a SimpleReport
	 *
	 * @param simpleReport {@link XmlSimpleReport}
	 */
	public void setSimpleReport(XmlSimpleReport simpleReport) {
		this.simpleReport = simpleReport;
	}

	/**
	 * Gets a DetailedReport
	 *
	 * @return {@link XmlDetailedReport}
	 */
	public XmlDetailedReport getDetailedReport() {
		return detailedReport;
	}

	/**
	 * Sets a DetailedReport
	 *
	 * @param detailedReport {@link XmlDetailedReport}
	 */
	public void setDetailedReport(XmlDetailedReport detailedReport) {
		this.detailedReport = detailedReport;
	}

	/**
	 * Gets a Validation report data handler
	 *
	 * @return {@link DataHandler}
	 */
	public DataHandler getValidationReportDataHandler() {
		return validationReportDataHandler;
	}

	/**
	 * Sets a validation report data handler
	 *
	 * @param validationReportDataHandler {@link DataHandler}
	 */
	public void setValidationReportDataHandler(DataHandler validationReportDataHandler) {
		this.validationReportDataHandler = validationReportDataHandler;
	}

	/**
	 * Gets the ETSI validation report
	 *
	 * @return {@link ValidationReportType}
	 */
	public ValidationReportType getValidationReport() {
		if ((validationReport == null) && (validationReportDataHandler != null)) {
			try {
				validationReport = ValidationReportFacade.newFacade().unmarshall(validationReportDataHandler.getInputStream());
			} catch (Exception e) {
				throw new DSSRemoteServiceException("Unable to unmarshall ValidationReportType", e);
			}
		}
		return validationReport;
	}

	/**
	 * Sets the ETSI validation report
	 *
	 * @param validationReport {@link ValidationReportType}
	 */
	public void setValidationReport(ValidationReportType validationReport) {
		this.validationReport = validationReport;
	}

}
