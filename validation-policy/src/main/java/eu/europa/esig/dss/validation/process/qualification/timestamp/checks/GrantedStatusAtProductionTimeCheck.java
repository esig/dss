package eu.europa.esig.dss.validation.process.qualification.timestamp.checks;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualification;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

public class GrantedStatusAtProductionTimeCheck extends ChainItem<XmlValidationTimestampQualification> {

	private final List<TrustedServiceWrapper> trustServicesAtTime;

	public GrantedStatusAtProductionTimeCheck(I18nProvider i18nProvider, XmlValidationTimestampQualification result,
			List<TrustedServiceWrapper> trustServicesAtTime, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.trustServicesAtTime = trustServicesAtTime;
	}

	@Override
	protected boolean process() {
		return Utils.isCollectionNotEmpty(trustServicesAtTime);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_HAS_GRANTED_AT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_HAS_GRANTED_AT_ANS;
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
