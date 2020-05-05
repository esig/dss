package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

public class RevocationCertHashPresenceCheck extends ChainItem<XmlRAC> {

	private final RevocationWrapper revocationData;

	public RevocationCertHashPresenceCheck(I18nProvider i18nProvider, XmlRAC result, RevocationWrapper revocationData, 
			LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.revocationData = revocationData;
	}

	@Override
	protected boolean process() {
		return revocationData.isCertHashExtensionPresent();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_REVOC_CERT_HASH_PRESENT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_REVOC_CERT_HASH_PRESENT_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.TRY_LATER;
	}

}
