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
package eu.europa.esig.dss.ws.cert.validation.soap.client;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;

@XmlAccessorType(XmlAccessType.FIELD)
@SuppressWarnings("serial")
public class WSCertificateReportsDTO implements Serializable {

	@XmlElement(name = "DiagnosticData", namespace = "http://dss.esig.europa.eu/validation/diagnostic")
	private XmlDiagnosticData diagnosticData;

	@XmlElement(name = "SimpleCertificateReport", namespace = "http://dss.esig.europa.eu/validation/simple-certificate-report")
	private XmlSimpleCertificateReport simpleCertificateReport;

	@XmlElement(name = "DetailedReport", namespace = "http://dss.esig.europa.eu/validation/detailed-report")
	private XmlDetailedReport detailedReport;
	
	public WSCertificateReportsDTO() {
	}
	
	public WSCertificateReportsDTO(XmlDiagnosticData diagnosticData, XmlSimpleCertificateReport simpleCertificateReport, 
			XmlDetailedReport detailedReport) {
		this.diagnosticData = diagnosticData;
		this.simpleCertificateReport = simpleCertificateReport;
		this.detailedReport = detailedReport;
	}
	
	public XmlDiagnosticData getDiagnosticData() {
		return diagnosticData;
	}

	public void setDiagnosticData(XmlDiagnosticData diagnosticData) {
		this.diagnosticData = diagnosticData;
	}
	
	public XmlSimpleCertificateReport getSimpleCertificateReport() {
		return simpleCertificateReport;
	}
	
	public void setSimpleCertificateReport(XmlSimpleCertificateReport simpleCertificateReport) {
		this.simpleCertificateReport = simpleCertificateReport;
	}

	public XmlDetailedReport getDetailedReport() {
		return detailedReport;
	}

	public void setDetailedReport(XmlDetailedReport detailedReport) {
		this.detailedReport = detailedReport;
	}

}
