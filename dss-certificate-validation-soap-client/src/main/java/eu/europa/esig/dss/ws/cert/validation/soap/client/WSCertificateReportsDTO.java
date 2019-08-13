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
