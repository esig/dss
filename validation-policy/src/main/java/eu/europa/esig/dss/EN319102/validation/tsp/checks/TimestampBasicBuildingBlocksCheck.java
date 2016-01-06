package eu.europa.esig.dss.EN319102.validation.tsp.checks;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class TimestampBasicBuildingBlocksCheck extends ChainItem<XmlValidationProcessTimestamps> {

	private final XmlBasicBuildingBlocks timestampBBB;

	public TimestampBasicBuildingBlocksCheck(XmlValidationProcessTimestamps result, XmlBasicBuildingBlocks timestampBBB, LevelConstraint constraint) {
		super(result, constraint);

		this.timestampBBB = timestampBBB;
	}

	@Override
	protected boolean process() {

		// Format check is skipped

		XmlISC isc = timestampBBB.getISC();
		XmlConclusion iscConclusion = isc.getConclusion();
		if (!Indication.VALID.equals(iscConclusion.getIndication())) {
			return false;
		}

		// VCI is skipped

		XmlCV cv = timestampBBB.getCV();
		XmlConclusion cvConclusion = cv.getConclusion();
		if (!Indication.VALID.equals(cvConclusion.getIndication())) {
			return false;
		}

		XmlXCV xcv = timestampBBB.getXCV();
		XmlConclusion xcvConclusion = xcv.getConclusion();
		if (!Indication.VALID.equals(xcvConclusion.getIndication())) {
			return false;
		}

		XmlSAV sav = timestampBBB.getSAV();
		XmlConclusion savConclusion = sav.getConclusion();
		if (!Indication.VALID.equals(savConclusion.getIndication())) {
			return false;
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
		return null;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}
}
