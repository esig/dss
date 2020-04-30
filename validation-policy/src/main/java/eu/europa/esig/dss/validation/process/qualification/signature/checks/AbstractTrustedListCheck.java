package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

public abstract class AbstractTrustedListCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	private final XmlTLAnalysis tlAnalysis;

	protected AbstractTrustedListCheck(I18nProvider i18nProvider, T result, XmlTLAnalysis tlAnalysis, LevelConstraint constraint) {
		super(i18nProvider, result, constraint, tlAnalysis.getId());

		this.tlAnalysis = tlAnalysis;
	}

	@Override
	public boolean process() {
		return isValidConclusion(tlAnalysis.getConclusion());
	}

	@Override
	protected MessageTag getAdditionalInfo() {
		return MessageTag.TRUSTED_LIST.setArgs(tlAnalysis.getURL());
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
