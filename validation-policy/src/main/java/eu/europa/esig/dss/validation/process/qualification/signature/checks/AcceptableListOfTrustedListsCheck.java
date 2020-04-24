package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

public class AcceptableListOfTrustedListsCheck<T extends XmlConstraintsConclusion> extends AbstractTrustedListCheck<T> {

	public AcceptableListOfTrustedListsCheck(I18nProvider i18nProvider, T result, XmlTLAnalysis lotlAnalysis, LevelConstraint constraint) {
		super(i18nProvider, result, lotlAnalysis, constraint);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_LIST_OF_TRUSTED_LISTS_ACCEPT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_LIST_OF_TRUSTED_LISTS_ACCEPT_ANS;
	}

}
