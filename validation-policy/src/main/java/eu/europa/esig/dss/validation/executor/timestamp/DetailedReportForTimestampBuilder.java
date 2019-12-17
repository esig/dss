package eu.europa.esig.dss.validation.executor.timestamp;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.AbstractDetailedReportBuilder;
import eu.europa.esig.dss.validation.process.qualification.timestamp.TimestampQualificationBlock;
import eu.europa.esig.dss.validation.process.vpftsp.ValidationProcessForTimeStamps;

public class DetailedReportForTimestampBuilder extends AbstractDetailedReportBuilder {

	public DetailedReportForTimestampBuilder(I18nProvider i18nProvider, DiagnosticData diagnosticData, ValidationPolicy policy, Date currentTime) {
		super(i18nProvider, currentTime, policy, diagnosticData);
	}

	XmlDetailedReport build() {

		XmlDetailedReport detailedReport = init();

		Map<String, XmlBasicBuildingBlocks> bbbs = executeAllBasicBuildingBlocks();
		detailedReport.getBasicBuildingBlocks().addAll(bbbs.values());

		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();

		if (Utils.isCollectionNotEmpty(timestamps)) {
			for (TimestampWrapper timestamp : timestamps) {
				XmlTimestamp timestampAnalysis = new XmlTimestamp();

				// TODO : long-term validation
				ValidationProcessForTimeStamps vpftsp = new ValidationProcessForTimeStamps(i18nProvider, timestamp, bbbs.get(timestamp.getId()));
				timestampAnalysis.setValidationProcessTimestamps(vpftsp.execute());

				if (policy.isEIDASConstraintPresent()) {
					TimestampQualificationBlock timestampQualificationBlock = new TimestampQualificationBlock(i18nProvider, timestamp,
							detailedReport.getTLAnalysis());
					timestampAnalysis.setValidationTimestampQualification(timestampQualificationBlock.execute());
				}

				detailedReport.getTimestamps().add(timestampAnalysis);
			}
		}

		return detailedReport;
	}

	private Map<String, XmlBasicBuildingBlocks> executeAllBasicBuildingBlocks() {
		Map<String, XmlBasicBuildingBlocks> bbbs = new LinkedHashMap<String, XmlBasicBuildingBlocks>();
		process(diagnosticData.getAllRevocationData(), Context.REVOCATION, bbbs);
		process(diagnosticData.getTimestampList(), Context.TIMESTAMP, bbbs);
		return bbbs;
	}

}
