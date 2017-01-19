package eu.europa.esig.dss.validation.process.art32.qualification.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class AdESAcceptableCheck extends ChainItem<XmlSignatureAnalysis> implements Condition {

	private final XmlConclusion etsi319102Conclusion;

	public AdESAcceptableCheck(XmlSignatureAnalysis result, XmlConclusion etsi319102Conclusion, LevelConstraint constraint) {
		super(result, constraint);

		this.etsi319102Conclusion = etsi319102Conclusion;
	}

	@Override
	public boolean check() {
		return process();
	}

	@Override
	protected boolean process() {
		return isAcceptableConclusion(etsi319102Conclusion);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_IS_ADES;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_IS_ADES_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return etsi319102Conclusion.getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return etsi319102Conclusion.getSubIndication();
	}

}
