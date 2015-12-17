package eu.europa.esig.dss.EN319102.bbb.isc.checks;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SigningCertificateSignedCheck extends ChainItem<XmlISC> {

	private static final String XMLE_X509CERTIFICATE = "X509Certificate";
	private static final String XMLE_X509DATA = "X509Data";
	private static final String XMLE_KEYINFO = "KeyInfo";

	private final TokenProxy token;

	public SigningCertificateSignedCheck(XmlISC result, TokenProxy token, LevelConstraint constraint) {
		super(result, constraint);
		this.token = token;
	}

	@Override
	protected boolean process() {
		String signedElement = token.getSigningCertificateSigned();
		return XMLE_X509CERTIFICATE.equals(signedElement) || XMLE_X509DATA.equals(signedElement) || XMLE_KEYINFO.equals(signedElement);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_ICS_ISCS;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_ICS_ISCS_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.FORMAT_FAILURE;
	}

}
