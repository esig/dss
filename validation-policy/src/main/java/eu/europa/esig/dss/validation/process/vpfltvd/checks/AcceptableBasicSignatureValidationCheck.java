package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class AcceptableBasicSignatureValidationCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final XmlConstraintsConclusion basicSignatureValidation;

	private Indication indication;
	private SubIndication subIndication;
	private List<XmlName> bsErrors;

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

			boolean allowed = Indication.PASSED.equals(bbbIndication)
					|| (Indication.INDETERMINATE.equals(bbbIndication) && (SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(bbbSubIndication)
							|| SubIndication.REVOKED_NO_POE.equals(bbbSubIndication) || SubIndication.OUT_OF_BOUNDS_NO_POE.equals(bbbSubIndication)));

			if (!allowed) {
				indication = bbbIndication;
				subIndication = bbbSubIndication;
				bsErrors = basicSignatureValidationConclusion.getErrors();
			}
			return allowed;
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.LTV_ABSV;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.LTV_ABSV_ANS;
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
		return bsErrors;
	}

}
