package eu.europa.esig.dss.EN319102;

import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTimestamp;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTimestampsValidation;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.TimestampWrapper;
import eu.europa.esig.dss.validation.report.DiagnosticData;

/**
 * 5.4 Validation process for time-stamps
 */
public class ValidationProcessForTimeStamps {

	private final DiagnosticData diagnosticData;

	private final SignatureWrapper signature;

	// Only tsps with correct imprints
	private final List<TimestampWrapper> timestampList;

	private final ValidationPolicy policy;

	private final Date currentTime;

	public ValidationProcessForTimeStamps(DiagnosticData diagnosticData, SignatureWrapper signature, List<TimestampWrapper> timestampList,
			ValidationPolicy policy, Date currentTime) {
		this.diagnosticData = diagnosticData;
		this.signature = signature;
		this.timestampList = timestampList;
		this.policy = policy;
		this.currentTime = currentTime;
	}

	public XmlTimestampsValidation execute() {
		XmlTimestampsValidation result = new XmlTimestampsValidation();

		if (CollectionUtils.isNotEmpty(timestampList)) {
			for (TimestampWrapper tsp : timestampList) {

				BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, tsp, currentTime, policy, Context.TIMESTAMP);
				XmlBasicBuildingBlocks basicBuildingBlocks = bbb.execute();

				XmlTimestamp timestampAnalysis = new XmlTimestamp();
				timestampAnalysis.setId(tsp.getId());
				timestampAnalysis.setType(tsp.getType());
				timestampAnalysis.setSignatureId(signature.getId());
				timestampAnalysis.setBasicBuildingBlocks(basicBuildingBlocks);

				result.getTimestamps().add(timestampAnalysis);
			}
		}

		return result;
	}

}
