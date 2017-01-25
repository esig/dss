package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateExpirationCheck extends ChainItem<XmlSubXCV> {

	private final Date currentTime;
	private final CertificateWrapper certificate;

	public CertificateExpirationCheck(XmlSubXCV result, CertificateWrapper certificate, Date currentTime, LevelConstraint constraint) {
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
	protected String getAdditionalInfo() {
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		String notBeforeStr = certificate.getNotBefore() == null ? " ? " : sdf.format(certificate.getNotBefore());
		String notAfterStr = certificate.getNotAfter() == null ? " ? " : sdf.format(certificate.getNotAfter());
		Object[] params = new Object[] { notBeforeStr, notAfterStr };
		return MessageFormat.format(AdditionalInfo.CERTIFICATE_VALIDITY, params);
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
