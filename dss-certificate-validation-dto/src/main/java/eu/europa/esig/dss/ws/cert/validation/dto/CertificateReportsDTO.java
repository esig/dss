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
package eu.europa.esig.dss.ws.cert.validation.dto;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;

import java.io.Serializable;

/**
 * The DTO representing the validation response result
 */
public class CertificateReportsDTO implements Serializable {

	private static final long serialVersionUID = 6655102454289129851L;

	/** The DiagnosticData report */
	private XmlDiagnosticData diagnosticData;

	/** The Simple Certificate report */
	private XmlSimpleCertificateReport simpleCertificateReport;

	/** The Detailed report */
	private XmlDetailedReport detailedReport;

	/**
	 * Empty constructor
	 */
	public CertificateReportsDTO() {
	}

	/**
	 * The default constructor
	 *
	 * @param diagnosticData {@link XmlDiagnosticData}
	 * @param simpleCertificateReport {@link XmlSimpleCertificateReport}
	 * @param detailedReport {@link XmlDetailedReport}
	 */
	public CertificateReportsDTO(XmlDiagnosticData diagnosticData, XmlSimpleCertificateReport simpleCertificateReport,
								 XmlDetailedReport detailedReport) {
		this.diagnosticData = diagnosticData;
		this.simpleCertificateReport = simpleCertificateReport;
		this.detailedReport = detailedReport;
	}

	/**
	 * Gets the DiagnosticData report
	 *
	 * @return {@link XmlDiagnosticData}
	 */
	public XmlDiagnosticData getDiagnosticData() {
		return diagnosticData;
	}

	/**
	 * Sets the DiagnosticData report
	 *
	 * @param diagnosticData {@link XmlDiagnosticData}
	 */
	public void setDiagnosticData(XmlDiagnosticData diagnosticData) {
		this.diagnosticData = diagnosticData;
	}

	/**
	 * Gets the Simple Certificate report
	 *
	 * @return {@link XmlSimpleCertificateReport}
	 */
	public XmlSimpleCertificateReport getSimpleCertificateReport() {
		return simpleCertificateReport;
	}

	/**
	 * Sets the Simple Certificate report
	 *
	 * @param simpleCertificateReport {@link XmlSimpleCertificateReport}
	 */
	public void setSimpleCertificateReport(XmlSimpleCertificateReport simpleCertificateReport) {
		this.simpleCertificateReport = simpleCertificateReport;
	}

	/**
	 * Gets the Detailed report
	 *
	 * @return {@link XmlDetailedReport}
	 */
	public XmlDetailedReport getDetailedReport() {
		return detailedReport;
	}

	/**
	 * Sets the Detailed report
	 *
	 * @param detailedReport {@link XmlDetailedReport}
	 */
	public void setDetailedReport(XmlDetailedReport detailedReport) {
		this.detailedReport = detailedReport;
	}

}
