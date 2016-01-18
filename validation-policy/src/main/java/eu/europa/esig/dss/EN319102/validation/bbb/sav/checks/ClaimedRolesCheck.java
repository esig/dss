package eu.europa.esig.dss.EN319102.validation.bbb.sav.checks;

import java.util.List;

import eu.europa.esig.dss.MessageTag;
import eu.europa.esig.dss.EN319102.validation.bbb.AbstractMultiValuesCheckItem;
import eu.europa.esig.dss.EN319102.wrappers.SignatureWrapper;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class ClaimedRolesCheck extends AbstractMultiValuesCheckItem<XmlSAV> {

	private final SignatureWrapper signature;
	private final MultiValuesConstraint constraint;

	public ClaimedRolesCheck(XmlSAV result, SignatureWrapper signature, MultiValuesConstraint constraint) {
		super(result, constraint);
		this.signature = signature;
		this.constraint = constraint;
	}

	@Override
	protected boolean process() {
		List<String> claimedRoles = signature.getClaimedRoles();
		List<String> expectedValues = constraint.getId();
		return processValuesCheck(claimedRoles, expectedValues);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_SAV_ICRM;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_SAV_ICRM_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
