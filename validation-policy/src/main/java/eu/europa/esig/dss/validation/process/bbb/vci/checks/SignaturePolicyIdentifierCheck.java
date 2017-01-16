package eu.europa.esig.dss.validation.process.bbb.vci.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class SignaturePolicyIdentifierCheck extends AbstractMultiValuesCheckItem<XmlVCI> {

	private final SignatureWrapper signature;
	private final MultiValuesConstraint multiValues;

	public SignaturePolicyIdentifierCheck(XmlVCI result, SignatureWrapper signature, MultiValuesConstraint multiValues) {
		super(result, multiValues);
		this.signature = signature;
		this.multiValues = multiValues;
	}

	@Override
	protected boolean process() {
		String policyId = signature.getPolicyId();
		if (multiValues.getId().contains(SignaturePolicy.NO_POLICY) && Utils.isStringEmpty(policyId)) {
			return true;
		} else if (multiValues.getId().contains(SignaturePolicy.ANY_POLICY) && Utils.isStringNotEmpty(policyId)) {
			return true;
		} else if (multiValues.getId().contains(SignaturePolicy.IMPLICIT_POLICY) && Utils.areStringsEqual(SignaturePolicy.IMPLICIT_POLICY, policyId)) {
			return true;
		}
		// oids
		return processValueCheck(policyId);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_VCI_ISPK;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_VCI_ISPK_ANS_1;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.POLICY_PROCESSING_ERROR;
	}

}
