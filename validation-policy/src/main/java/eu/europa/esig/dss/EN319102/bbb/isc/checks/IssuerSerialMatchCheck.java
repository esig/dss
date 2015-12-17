package eu.europa.esig.dss.EN319102.bbb.isc.checks;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class IssuerSerialMatchCheck extends ChainItem<XmlISC> {

	private final TokenProxy token;

	public IssuerSerialMatchCheck(XmlISC result, TokenProxy token, LevelConstraint constraint) {
		super(result, constraint);
		this.token = token;
	}

	@Override
	protected boolean process() {
		return token.isIssuerSerialMatch();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_ICS_AIDNASNE;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_ICS_AIDNASNE_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_SIGNER_CERTIFICATE_FOUND;
	}
}
