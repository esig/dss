package eu.europa.esig.dss.validation.process.vpfswatsp.checks.erv.checks;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlERV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.TimestampComparator;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.PastSignatureValidation;
import eu.europa.esig.dss.validation.process.vpftsp.ValidationProcessForTimeStamps;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
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
			XmlBasicBuildingBlocks bbbTsp = bbbs.get(timestamp.getId());
			ValidationProcessForTimeStamps tspValidation = new ValidationProcessForTimeStamps(timestamp, bbbs);
			XmlValidationProcessTimestamps tspValidationResult = tspValidation.execute();

			if (!isValid(tspValidationResult)) {
				Date validationDate = yougestTSP == null ? currentTime : yougestTSP.getProductionTime();
				PastSignatureValidation psv = new PastSignatureValidation(timestamp, diagnosticData, bbbTsp, poe, validationDate, policy, Context.TIMESTAMP);
				XmlPSV psvResult = psv.execute();
				bbbTsp.setPSV(psvResult);
				if (!isValid(psvResult)) {
					return false;
				}
			}
			yougestTSP = timestamp;
		}

		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_ROTVPIIC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_ROTVPIIC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
