package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CurrentTimeIndicationCheck extends ChainItem<XmlPSV> {

	private final Indication indication;
	private final SubIndication subIndication;
	private final List<XmlName> errors;

	public CurrentTimeIndicationCheck(XmlPSV result, Indication indication, SubIndication subIndication, List<XmlName> errors, LevelConstraint constraint) {
		super(result, constraint);

		this.indication = indication;
		this.subIndication = subIndication;
		this.errors = errors;
	}

	@Override
	protected boolean process() {
		return Indication.PASSED.equals(indication);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.PSV_IPCVC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PSV_IPCVC_ANS;
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
