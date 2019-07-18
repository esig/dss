package eu.europa.esig.dss.dto;

import java.io.Serializable;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;

public class CertificateReportsDTO implements Serializable {

	private static final long serialVersionUID = 6655102454289129851L;
	
	private XmlDiagnosticData diagnosticData;
	private XmlSimpleCertificateReport simpleCertificateReport;
	private XmlDetailedReport detailedReport;
	
	public CertificateReportsDTO() {
	}
	
	public CertificateReportsDTO(XmlDiagnosticData diagnosticData, XmlSimpleCertificateReport simpleCertificateReport, XmlDetailedReport detailedReport) {
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
