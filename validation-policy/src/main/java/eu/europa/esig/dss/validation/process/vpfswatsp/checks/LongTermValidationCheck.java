package eu.europa.esig.dss.validation.process.vpfswatsp.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class LongTermValidationCheck extends ChainItem<XmlValidationProcessArchivalData> {

	private final XmlConstraintsConclusion longTermValidationResult;
	private Indication ltvIndication;
	private SubIndication ltvSubIndication;

	public LongTermValidationCheck(XmlValidationProcessArchivalData result, XmlConstraintsConclusion longTermValidationResult, LevelConstraint constraint) {
		super(result, constraint);

		this.longTermValidationResult = longTermValidationResult;
	}

	@Override
	protected boolean process() {
		if (longTermValidationResult != null && longTermValidationResult.getConclusion() != null) {
			ltvIndication = longTermValidationResult.getConclusion().getIndication();
			ltvSubIndication = longTermValidationResult.getConclusion().getSubIndication();

			return Indication.VALID.equals(ltvIndication)
					|| (Indication.INDETERMINATE.equals(ltvIndication) && (SubIndication.REVOKED_NO_POE.equals(ltvSubIndication)
							|| SubIndication.REVOKED_CA_NO_POE.equals(ltvSubIndication) || SubIndication.OUT_OF_BOUNDS_NO_POE.equals(ltvSubIndication)
							|| SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(ltvSubIndication)));
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ARCH_LTVV;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ARCH_LTVV_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return ltvIndication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return ltvSubIndication;
	}

}
