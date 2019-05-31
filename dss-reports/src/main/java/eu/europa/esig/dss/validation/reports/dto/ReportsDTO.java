package eu.europa.esig.dss.validation.reports.dto;

import java.io.Serializable;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;

public class ReportsDTO implements Serializable {

	private static final long serialVersionUID = -6854645201561656069L;

	private DiagnosticData diagnosticData;
	private SimpleReport simpleReport;
	private DetailedReport detailedReport;

	public ReportsDTO() {
	}

	public ReportsDTO(DiagnosticData diagnosticData, SimpleReport simpleReport, DetailedReport detailedReport) {
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
