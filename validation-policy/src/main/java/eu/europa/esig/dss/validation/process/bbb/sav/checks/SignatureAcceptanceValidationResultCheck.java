package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.IMessageTag;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SignatureAcceptanceValidationResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {
	
	private final XmlSAV savResult;

	public SignatureAcceptanceValidationResultCheck(T result, XmlSAV savResult, LevelConstraint constraint) {
		super(result, constraint);
		this.savResult = savResult;
	}

	@Override
	protected boolean process() {
		return isValid(savResult);
	}

	@Override
	protected IMessageTag getMessageTag() {
		return MessageTag.BBB_SAV_ISVA;
	}

	@Override
	protected IMessageTag getErrorMessageTag() {
		return MessageTag.BBB_SAV_ISVA_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return savResult.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return savResult.getConclusion().getSubIndication();
	}

	@Override
	protected List<XmlName> getPreviousErrors() {
		return savResult.getConclusion().getErrors();
	}
	
}
