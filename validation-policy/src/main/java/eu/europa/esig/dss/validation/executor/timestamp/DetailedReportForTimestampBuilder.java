package eu.europa.esig.dss.validation.executor.timestamp;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.executor.AbstractDetailedReportBuilder;
import eu.europa.esig.dss.validation.process.vpftsp.ValidationProcessForTimeStamps;

public class DetailedReportForTimestampBuilder extends AbstractDetailedReportBuilder {
	
	private final String timestampId;

	public DetailedReportForTimestampBuilder(DiagnosticData diagnosticData, ValidationPolicy policy, Date currentTime, String timestampId) {
		super(diagnosticData, policy, currentTime);
		this.timestampId = timestampId;
	}

	XmlDetailedReport build() {

		XmlDetailedReport detailedReport = init();

		Map<String, XmlBasicBuildingBlocks> bbbs = executeAllBasicBuildingBlocks();
		detailedReport.getBasicBuildingBlocks().addAll(bbbs.values());

		XmlSignature signatureAnalysis = new XmlSignature();
		
		TimestampWrapper timestamp = diagnosticData.getTimestampById(timestampId);
		executeTimestampsValidation(signatureAnalysis, bbbs, timestamp);
		
		// TODO : timestamp qualification
		
		detailedReport.getSignatures().add(signatureAnalysis);

		return detailedReport;
	}

	private Map<String, XmlBasicBuildingBlocks> executeAllBasicBuildingBlocks() {
		Map<String, XmlBasicBuildingBlocks> bbbs = new LinkedHashMap<String, XmlBasicBuildingBlocks>();
		process(diagnosticData.getAllRevocationData(), Context.REVOCATION, bbbs);
		process(diagnosticData.getTimestampList(), Context.TIMESTAMP, bbbs);
		return bbbs;
	}
	
	private void executeTimestampsValidation(XmlSignature signatureAnalysis, Map<String, XmlBasicBuildingBlocks> bbbs, TimestampWrapper timestamp) {
		ValidationProcessForTimeStamps vpftsp = new ValidationProcessForTimeStamps(timestamp, bbbs);
		signatureAnalysis.getValidationProcessTimestamps().add(vpftsp.execute());
	}

}
