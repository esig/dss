package eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.erv.checks;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.MessageTag;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.EN319102.validation.ChainItem;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.TimestampComparator;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.psv.PastSignatureValidation;
import eu.europa.esig.dss.EN319102.validation.vpftsp.ValidationProcessForTimeStamps;
import eu.europa.esig.dss.EN319102.wrappers.DiagnosticData;
import eu.europa.esig.dss.EN319102.wrappers.TimestampWrapper;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlERV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ArchiveTimestampsValidationCheck extends ChainItem<XmlERV> {

	private final List<TimestampWrapper> archiveTimestamps;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	private final DiagnosticData diagnosticData;
	private final POEExtraction poe;
	private final ValidationPolicy policy;
	private final Date currentTime;

	public ArchiveTimestampsValidationCheck(XmlERV result, List<TimestampWrapper> archiveTimestamps, Map<String, XmlBasicBuildingBlocks> bbbs,
			DiagnosticData diagnosticData, POEExtraction poe, ValidationPolicy policy, Date currentTime, LevelConstraint constraint) {
		super(result, constraint);

		this.archiveTimestamps = archiveTimestamps;
		this.bbbs = bbbs;

		this.diagnosticData = diagnosticData;
		this.poe = poe;
		this.policy = policy;
		this.currentTime = currentTime;
	}

	@Override
	protected boolean process() {

		Collections.sort(archiveTimestamps, new TimestampComparator());
		Collections.reverse(archiveTimestamps); // start by the youngest ATSP

		TimestampWrapper yougestTSP = null;
		for (TimestampWrapper timestamp : archiveTimestamps) {
			ValidationProcessForTimeStamps tspValidation = new ValidationProcessForTimeStamps(timestamp, bbbs);
			XmlValidationProcessTimestamps tspValidationResult = tspValidation.execute();

			if (!isValid(tspValidationResult)) {
				Date validationDate = yougestTSP == null ? currentTime : yougestTSP.getProductionTime();
				PastSignatureValidation psv = new PastSignatureValidation(timestamp, diagnosticData, poe, validationDate, policy, Context.TIMESTAMP);
				XmlPSV psvResult = psv.execute();
				if (!isValid(psvResult)) {
					return false;
				}
			}
			yougestTSP = timestamp;
		}

		return true;
	}

	private boolean isValid(XmlConstraintsConclusion constraintConclusion) {
		return constraintConclusion != null && constraintConclusion.getConclusion() != null
				&& Indication.VALID.equals(constraintConclusion.getConclusion().getIndication());
	}

	@Override
	protected MessageTag getMessageTag() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
