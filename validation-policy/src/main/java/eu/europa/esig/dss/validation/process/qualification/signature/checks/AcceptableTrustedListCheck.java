package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class AcceptableTrustedListCheck extends ChainItem<XmlValidationCertificateQualification> {

	private final XmlTLAnalysis tlAnalysis;

	public AcceptableTrustedListCheck(XmlValidationCertificateQualification result, XmlTLAnalysis tlAnalysis, LevelConstraint constraint) {
		super(result, constraint, tlAnalysis.getCountryCode());

		this.tlAnalysis = tlAnalysis;
	}

	@Override
	protected boolean process() {
		return isAcceptableConclusion(tlAnalysis.getConclusion());
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TRUSTED_LIST_ACCEPT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_TRUSTED_LIST_ACCEPT_ANS;
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
