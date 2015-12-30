package eu.europa.esig.dss.EN319102.bbb.vci.checks;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SignaturePolicyIdentifierCheck extends ChainItem<XmlVCI> {

	private final SignatureWrapper signature;

	public SignaturePolicyIdentifierCheck(XmlVCI result, LevelConstraint constraint, SignatureWrapper signature) {
		super(result, constraint);
		this.signature = signature;
	}

	@Override
	protected boolean process() {
		if (SignaturePolicy.IMPLICIT_POLICY.equals(signature.getPolicyId())) {
			return true;
		} else if (signature.isPolicyPresent()) {
			return signature.getPolicyStatus();
		} else {
			return false;
		}
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_VCI_ISPK;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return signature.isPolicyPresent() ? MessageTag.BBB_VCI_ISPK_ANS_2 : MessageTag.BBB_VCI_ISPK_ANS_1;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return signature.isPolicyPresent() ? SubIndication.POLICY_PROCESSING_ERROR : SubIndication.NO_POLICY;
	}

}
