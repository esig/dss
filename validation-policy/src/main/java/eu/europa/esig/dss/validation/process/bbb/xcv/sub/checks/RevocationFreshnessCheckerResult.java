package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationFreshnessCheckerResult extends ChainItem<XmlSubXCV> {

	private final XmlRFC rfcResult;

	public RevocationFreshnessCheckerResult(XmlSubXCV result, XmlRFC rfcResult, LevelConstraint constraint) {
		super(result, constraint);
		this.rfcResult = rfcResult;
	}

	@Override
	protected boolean process() {
		return isValid(rfcResult);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_RFC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_RFC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return rfcResult.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return rfcResult.getConclusion().getSubIndication();
	}

	@Override
	protected List<XmlName> getPreviousErrors() {
		return rfcResult.getConclusion().getErrors();
	}

}
