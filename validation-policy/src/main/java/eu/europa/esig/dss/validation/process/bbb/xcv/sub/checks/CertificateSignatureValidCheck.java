package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateSignatureValidCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	private final CertificateWrapper certificate;

	public CertificateSignatureValidCheck(T result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		return certificate.isSignatureValid();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_ICSI;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_ICSI_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE;
	}

}
