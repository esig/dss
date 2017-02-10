package eu.europa.esig.dss.validation.process.bbb.vci.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SignaturePolicyIdentifiedCheck extends ChainItem<XmlVCI> {

	private final SignatureWrapper signature;

	public SignaturePolicyIdentifiedCheck(XmlVCI result, SignatureWrapper signature, LevelConstraint constraint) {
		super(result, constraint);
		this.signature = signature;
	}

	@Override
	protected boolean process() {
		return signature.isPolicyPresent() && signature.isPolicyIdentified();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_VCI_ISPA;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_VCI_ISPA_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE;
	}

}
