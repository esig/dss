package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck extends ChainItem<XmlPSV> {

	private final Date bestSignatureTime;
	private final CertificateWrapper signingCertificate;

	public BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck(XmlPSV result, Date bestSignatureTime,
			CertificateWrapper signingCertificate, LevelConstraint constraint) {
		super(result, constraint);

		this.bestSignatureTime = bestSignatureTime;
		this.signingCertificate = signingCertificate;
	}

	@Override
	protected boolean process() {
		return bestSignatureTime.after(signingCertificate.getNotBefore()) && bestSignatureTime.before(signingCertificate.getNotAfter());
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.TSV_ISCNVABST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.TSV_ISCNVABST_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.OUT_OF_BOUNDS_NO_POE;
	}

}
