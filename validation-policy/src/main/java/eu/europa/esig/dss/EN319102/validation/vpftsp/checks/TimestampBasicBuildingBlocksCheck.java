package eu.europa.esig.dss.EN319102.validation.vpftsp.checks;

import eu.europa.esig.dss.MessageTag;
import eu.europa.esig.dss.EN319102.validation.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class TimestampBasicBuildingBlocksCheck extends ChainItem<XmlValidationProcessTimestamps> {

	private final XmlBasicBuildingBlocks timestampBBB;

	private Indication indication;
	private SubIndication subIndication;

	public TimestampBasicBuildingBlocksCheck(XmlValidationProcessTimestamps result, XmlBasicBuildingBlocks timestampBBB, LevelConstraint constraint) {
		super(result, constraint, timestampBBB.getId());

		this.timestampBBB = timestampBBB;
	}

	@Override
	protected boolean process() {

		// Format check is skipped

		XmlISC isc = timestampBBB.getISC();
		XmlConclusion iscConclusion = isc.getConclusion();
		if (!Indication.VALID.equals(iscConclusion.getIndication())) {
			indication = iscConclusion.getIndication();
			subIndication = iscConclusion.getSubIndication();
			return false;
		}

		// VCI is skipped

		XmlCV cv = timestampBBB.getCV();
		XmlConclusion cvConclusion = cv.getConclusion();
		if (!Indication.VALID.equals(cvConclusion.getIndication())) {
			indication = cvConclusion.getIndication();
			subIndication = cvConclusion.getSubIndication();
			return false;
		}

		XmlXCV xcv = timestampBBB.getXCV();
		XmlConclusion xcvConclusion = xcv.getConclusion();
		if (!Indication.VALID.equals(xcvConclusion.getIndication())) {
			indication = xcvConclusion.getIndication();
			subIndication = xcvConclusion.getSubIndication();
			return false;
		}

		XmlSAV sav = timestampBBB.getSAV();
		XmlConclusion savConclusion = sav.getConclusion();
		if (!Indication.VALID.equals(savConclusion.getIndication())) {
			indication = savConclusion.getIndication();
			subIndication = savConclusion.getSubIndication();
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
		return indication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return subIndication;
	}

}
