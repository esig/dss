package eu.europa.esig.dss.validation;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;

@XmlRootElement(name = "WSReportsDTO", namespace = "http://validation.dss.esig.europa.eu/")
@XmlAccessorType(XmlAccessType.FIELD)
public class WSReportsDTO {

	@XmlElement(namespace = "http://dss.esig.europa.eu/validation/diagnostic")
	private DiagnosticData diagnosticData;

	@XmlElement(namespace = "http://dss.esig.europa.eu/validation/simple-report")
	private SimpleReport simpleReport;

	@XmlElement(namespace = "http://dss.esig.europa.eu/validation/detailed-report")
	private DetailedReport detailedReport;

	public WSReportsDTO() {
	}

	public WSReportsDTO(DiagnosticData diagnosticData, SimpleReport simpleReport, DetailedReport detailedReport) {
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
		this.simpleReport = simpleReport;
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

}
