package eu.europa.esig.dss.validation.executor;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlValidationPolicy;

public abstract class AbstractSimpleReportBuilder {

	private final Date currentTime;
	private final ValidationPolicy policy;
	protected final DiagnosticData diagnosticData;
	protected final DetailedReport detailedReport;
	
	public AbstractSimpleReportBuilder(Date currentTime, ValidationPolicy policy, DiagnosticData diagnosticData, DetailedReport detailedReport) {
		this.currentTime = currentTime;
		this.policy = policy;
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
	}

	/**
	 * This method generates the validation simpleReport.
	 *
	 * @return the object representing {@code XmlSimpleReport}
	 */
	public XmlSimpleReport build() {

		XmlSimpleReport simpleReport = new XmlSimpleReport();

		addPolicyNode(simpleReport);
		addValidationTime(simpleReport);
		addDocumentName(simpleReport);

		boolean containerInfoPresent = diagnosticData.isContainerInfoPresent();
		if (containerInfoPresent) {
			addContainerType(simpleReport);
		}

		return simpleReport;
	}

	private void addPolicyNode(XmlSimpleReport report) {
		XmlValidationPolicy xmlpolicy = new XmlValidationPolicy();
		xmlpolicy.setPolicyName(policy.getPolicyName());
		xmlpolicy.setPolicyDescription(policy.getPolicyDescription());
		report.setValidationPolicy(xmlpolicy);
	}

	private void addValidationTime(XmlSimpleReport report) {
		report.setValidationTime(currentTime);
	}

	private void addDocumentName(XmlSimpleReport report) {
		report.setDocumentName(diagnosticData.getDocumentName());
	}

	private void addContainerType(XmlSimpleReport simpleReport) {
		simpleReport.setContainerType(diagnosticData.getContainerType());
	}

}
