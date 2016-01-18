package eu.europa.esig.dss.validation.process.bbb.isc.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.wrappers.TokenProxy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SigningCertificateAttributePresentCheck extends ChainItem<XmlISC> {

	private final TokenProxy token;

	public SigningCertificateAttributePresentCheck(XmlISC result, TokenProxy token, LevelConstraint constraint) {
		super(result, constraint);
		this.token = token;
	}

	@Override
	protected boolean process() {
		return token.isAttributePresent();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_ICS_ISASCP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_ICS_ISASCP_ANS;
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
