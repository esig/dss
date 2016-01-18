package eu.europa.esig.dss.EN319102.validation.vpfltvd.checks;

import eu.europa.esig.dss.MessageTag;
import eu.europa.esig.dss.EN319102.validation.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class AcceptableBasicSignatureValidationCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final XmlConstraintsConclusion basicSignatureValidation;

	private Indication indication;
	private SubIndication subIndication;

	public AcceptableBasicSignatureValidationCheck(XmlValidationProcessLongTermData result, XmlConstraintsConclusion basicSignatureValidation,
			LevelConstraint constraint) {
		super(result, constraint);

		this.basicSignatureValidation = basicSignatureValidation;
	}

	@Override
	protected boolean process() {
		if (basicSignatureValidation != null && basicSignatureValidation.getConclusion() != null) {
			XmlConclusion basicSignatureValidationConclusion = basicSignatureValidation.getConclusion();
			Indication bbbIndication = basicSignatureValidationConclusion.getIndication();
			SubIndication bbbSubIndication = basicSignatureValidationConclusion.getSubIndication();

			boolean allowed = Indication.VALID.equals(bbbIndication)
					|| (Indication.INDETERMINATE.equals(bbbIndication) && (SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(bbbSubIndication)
							|| SubIndication.REVOKED_NO_POE.equals(bbbSubIndication) || SubIndication.OUT_OF_BOUNDS_NO_POE.equals(bbbSubIndication)));

			if (!allowed) {
				indication = bbbIndication;
				subIndication = bbbSubIndication;
			}
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_ROBVPIIC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_ROBVPIIC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return indication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return subIndication;
	}

}
