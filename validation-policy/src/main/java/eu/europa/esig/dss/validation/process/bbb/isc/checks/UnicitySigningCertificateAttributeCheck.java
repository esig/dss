package eu.europa.esig.dss.validation.process.bbb.isc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

public class UnicitySigningCertificateAttributeCheck extends ChainItem<XmlISC> {

	private final TokenProxy token;

	public UnicitySigningCertificateAttributeCheck(I18nProvider i18nProvider, XmlISC result, TokenProxy token, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.token = token;
	}

	@Override
	protected boolean process() {
		return token.isSigningCertificateReferenceUnique();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_ICS_ISASCPU;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_ICS_ISASCPU_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_SIGNING_CERTIFICATE_FOUND;
	}

}
