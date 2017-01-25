package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CheckSubXCVResult extends ChainItem<XmlXCV> {

	private final XmlSubXCV subResult;

	public CheckSubXCVResult(XmlXCV result, XmlSubXCV subResult, LevelConstraint constraint) {
		super(result, constraint, subResult.getId());

		this.subResult = subResult;
	}

	@Override
	protected boolean process() {
		return isValid(subResult);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_SUB;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_SUB_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return subResult.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return subResult.getConclusion().getSubIndication();
	}

	@Override
	protected List<XmlName> getPreviousErrors() {
		return subResult.getConclusion().getErrors();
	}

}
