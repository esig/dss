package eu.europa.esig.dss.EN319102.validation.vpfltvd.checks;

import java.util.Date;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class BestSignatureTimeBeforeIssuanceDateOfSigningCertificateCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final CertificateWrapper certificate;
	private final Date bestSignatureTime;

	public BestSignatureTimeBeforeIssuanceDateOfSigningCertificateCheck(XmlValidationProcessLongTermData result, CertificateWrapper certificate,
			Date bestSignatureTime, LevelConstraint constraint) {
		super(result, constraint);

		this.certificate = certificate;
		this.bestSignatureTime = bestSignatureTime;
	}

	@Override
	protected boolean process() {
		Date notBeforeTime = certificate.getNotBefore();
		return !bestSignatureTime.before(notBeforeTime);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.TSV_IBSTAIDOSC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.TSV_IBSTAIDOSC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NOT_YET_VALID;
	}

}
