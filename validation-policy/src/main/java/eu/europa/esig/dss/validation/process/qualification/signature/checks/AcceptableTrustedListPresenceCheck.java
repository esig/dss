package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import java.util.Set;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

public class AcceptableTrustedListPresenceCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	private final Set<String> validTLUrls;

	public AcceptableTrustedListPresenceCheck(I18nProvider i18nProvider, T result, Set<String> validTLUrls, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.validTLUrls = validTLUrls;
	}

	@Override
	public boolean process() {
		return Utils.isCollectionNotEmpty(validTLUrls);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_VALID_TRUSTED_LIST_PRESENT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_VALID_TRUSTED_LIST_PRESENT_ANS;
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