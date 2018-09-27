package eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlPCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ProspectiveCertificateChainCheck extends ChainItem<XmlPCV> {

	private final TokenProxy token;

	public ProspectiveCertificateChainCheck(XmlPCV result, TokenProxy token, LevelConstraint constraint) {
		super(result, constraint);
		this.token = token;
	}

	@Override
	protected boolean process() {
		return token.isTrustedChain();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_CCCBB;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_CCCBB_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_CERTIFICATE_CHAIN_FOUND;
	}

}
