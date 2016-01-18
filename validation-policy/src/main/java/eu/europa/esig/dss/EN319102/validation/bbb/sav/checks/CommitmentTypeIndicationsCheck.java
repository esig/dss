package eu.europa.esig.dss.EN319102.validation.bbb.sav.checks;

import java.util.List;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.MessageTag;
import eu.europa.esig.dss.EN319102.validation.ChainItem;
import eu.europa.esig.dss.EN319102.wrappers.SignatureWrapper;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class CommitmentTypeIndicationsCheck extends ChainItem<XmlSAV> {

	private final SignatureWrapper signature;
	private final MultiValuesConstraint constraint;

	public CommitmentTypeIndicationsCheck(XmlSAV result, SignatureWrapper signature, MultiValuesConstraint constraint) {
		super(result, constraint);
		this.signature = signature;
		this.constraint = constraint;
	}

	@Override
	protected boolean process() {
		List<String> commitmentTypeIdentifiers = signature.getCommitmentTypeIdentifiers();
		List<String> expectedValues = constraint.getId();

		if (CollectionUtils.isEmpty(commitmentTypeIdentifiers)) {
			return false;
		}

		if (CollectionUtils.isNotEmpty(expectedValues)) {
			return expectedValues.containsAll(commitmentTypeIdentifiers);
		}

		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_SAV_ISQPXTIP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_SAV_ISQPXTIP_ANS;
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
