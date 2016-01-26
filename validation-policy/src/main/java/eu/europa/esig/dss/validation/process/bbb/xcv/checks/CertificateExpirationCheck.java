package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateExpirationCheck extends ChainItem<XmlXCV> {

	private final Date currentTime;
	private final CertificateWrapper certificate;

	public CertificateExpirationCheck(XmlXCV result, CertificateWrapper certificate, Date currentTime, LevelConstraint constraint) {
		super(result, constraint);
		this.currentTime = currentTime;
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		Date notBefore = certificate.getNotBefore();
		Date notAfter = certificate.getNotAfter();
		boolean certificateValidity = (notBefore != null && (currentTime.compareTo(notBefore) >= 0))
				&& (notAfter != null && (currentTime.compareTo(notAfter) <= 0));
		return certificateValidity;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_ICTIVRSC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_ICTIVRSC_ANS;
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
