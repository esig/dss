package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationBasicBuildingBlocksCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final XmlBasicBuildingBlocks revocationBBB;

	private Indication indication;
	private SubIndication subIndication;
	private List<XmlName> errors;

	public RevocationBasicBuildingBlocksCheck(XmlValidationProcessLongTermData result, XmlBasicBuildingBlocks revocationBBB, LevelConstraint constraint) {
		super(result, constraint, revocationBBB.getId());

		this.revocationBBB = revocationBBB;
	}

	@Override
	protected boolean process() {

		// Format check is skipped

		XmlISC isc = revocationBBB.getISC();
		XmlConclusion iscConclusion = isc.getConclusion();
		if (!isAllowed(iscConclusion)) {
			indication = iscConclusion.getIndication();
			subIndication = iscConclusion.getSubIndication();
			errors = iscConclusion.getErrors();
			return false;
		}

		// VCI is skipped

		XmlCV cv = revocationBBB.getCV();
		XmlConclusion cvConclusion = cv.getConclusion();
		if (!isAllowed(cvConclusion)) {
			indication = cvConclusion.getIndication();
			subIndication = cvConclusion.getSubIndication();
			errors = cvConclusion.getErrors();
			return false;
		}

		XmlXCV xcv = revocationBBB.getXCV();
		XmlConclusion xcvConclusion = xcv.getConclusion();
		if (!isAllowed(xcvConclusion)) {
			indication = xcvConclusion.getIndication();
			subIndication = xcvConclusion.getSubIndication();
			errors = xcvConclusion.getErrors();
			return false;
		}

		XmlSAV sav = revocationBBB.getSAV();
		XmlConclusion savConclusion = sav.getConclusion();
		if (!isAllowed(savConclusion)) {
			indication = savConclusion.getIndication();
			subIndication = savConclusion.getSubIndication();
			errors = savConclusion.getErrors();
			return false;
		}

		return true;
	}

	private boolean isAllowed(XmlConclusion conclusion) {
		boolean allowed = Indication.PASSED.equals(conclusion.getIndication()) || (Indication.INDETERMINATE.equals(conclusion.getIndication())
				&& (SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.REVOKED_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.OUT_OF_BOUNDS_NO_POE.equals(conclusion.getSubIndication())));
		return allowed;
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

	@Override
	protected List<XmlName> getPreviousErrors() {
		return errors;
	}

}
