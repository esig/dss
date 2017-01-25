package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class ClaimedRolesCheck extends AbstractMultiValuesCheckItem<XmlSAV> {

	private final SignatureWrapper signature;

	public ClaimedRolesCheck(XmlSAV result, SignatureWrapper signature, MultiValuesConstraint constraint) {
		super(result, constraint);
		this.signature = signature;
	}

	@Override
	protected boolean process() {
		List<String> claimedRoles = signature.getClaimedRoles();
		return processValuesCheck(claimedRoles);
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
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
