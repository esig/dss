package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationBasicBuildingBlocksCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final XmlBasicBuildingBlocks revocationBBB;

	private Indication indication;
	private SubIndication subIndication;

	public RevocationBasicBuildingBlocksCheck(XmlValidationProcessLongTermData result, XmlBasicBuildingBlocks revocationBBB, LevelConstraint constraint) {
		super(result, constraint, revocationBBB.getId());

		this.revocationBBB = revocationBBB;
	}

	@Override
	protected boolean process() {

		// Format check is skipped

		XmlISC isc = revocationBBB.getISC();
		XmlConclusion iscConclusion = isc.getConclusion();
		if (!Indication.VALID.equals(iscConclusion.getIndication())) {
			indication = iscConclusion.getIndication();
			subIndication = iscConclusion.getSubIndication();
			return false;
		}

		// VCI is skipped

		XmlRFC rfc = revocationBBB.getRFC();
		XmlConclusion rfcConclusion = rfc.getConclusion();
		if (!Indication.VALID.equals(rfcConclusion.getIndication())) {
			indication = rfcConclusion.getIndication();
			subIndication = rfcConclusion.getSubIndication();
			return false;
		}

		XmlCV cv = revocationBBB.getCV();
		XmlConclusion cvConclusion = cv.getConclusion();
		if (!Indication.VALID.equals(cvConclusion.getIndication())) {
			indication = cvConclusion.getIndication();
			subIndication = cvConclusion.getSubIndication();
			return false;
		}

		XmlXCV xcv = revocationBBB.getXCV();
		XmlConclusion xcvConclusion = xcv.getConclusion();
		if (!Indication.VALID.equals(xcvConclusion.getIndication())) {
			indication = xcvConclusion.getIndication();
			subIndication = xcvConclusion.getSubIndication();
			return false;
		}

		XmlSAV sav = revocationBBB.getSAV();
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
		return MessageTag.ADEST_RORPIIC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_RORPIIC_ANS;
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
