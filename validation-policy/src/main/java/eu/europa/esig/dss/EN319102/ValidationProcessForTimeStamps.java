package eu.europa.esig.dss.EN319102;

import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTimestamp;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTimestampsValidation;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.TimestampWrapper;
import eu.europa.esig.dss.validation.policy.rules.AttributeValue;
import eu.europa.esig.dss.validation.report.DiagnosticData;

/**
 * 5.4 Validation process for time-stamps
 */
public class ValidationProcessForTimeStamps {

	private final DiagnosticData diagnosticData;

	private final ValidationPolicy mainPolicy;
	private final ValidationPolicy countersignaturePolicy;

	private final Date currentTime;

	public ValidationProcessForTimeStamps(DiagnosticData diagnosticData, ValidationPolicy mainPolicy, ValidationPolicy countersignaturePolicy,
			Date currentTime) {
		this.diagnosticData = diagnosticData;
		this.mainPolicy = mainPolicy;
		this.countersignaturePolicy = countersignaturePolicy;
		this.currentTime = currentTime;
	}

	public XmlTimestampsValidation execute() {

		XmlTimestampsValidation result = new XmlTimestampsValidation();

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (SignatureWrapper signature : signatures) {
				XmlSignature signatureAnalysis = new XmlSignature();
				signatureAnalysis.setId(signature.getId());

				ValidationPolicy currentPolicy = mainPolicy;
				if (AttributeValue.COUNTERSIGNATURE.equals(signature.getType())) {
					currentPolicy = countersignaturePolicy;
				}

				List<TimestampWrapper> timestampList = signature.getTimestampList();
				if (CollectionUtils.isNotEmpty(timestampList)) {
					for (TimestampWrapper tsp : timestampList) {

						BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, tsp, currentTime, currentPolicy, Context.TIMESTAMP);
						XmlBasicBuildingBlocks basicBuildingBlocks = bbb.execute();

						XmlTimestamp timestampAnalysis = new XmlTimestamp();
						timestampAnalysis.setId(tsp.getId());
						timestampAnalysis.setType(tsp.getType());
						timestampAnalysis.setSignatureId(signature.getId());
						timestampAnalysis.setBasicBuildingBlocks(basicBuildingBlocks);

						result.getTimestamps().add(timestampAnalysis);
					}
				}
			}
		}

		return result;
	}

}
