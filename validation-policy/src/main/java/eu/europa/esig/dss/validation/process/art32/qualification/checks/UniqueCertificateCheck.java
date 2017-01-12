package eu.europa.esig.dss.validation.process.art32.qualification.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class UniqueCertificateCheck extends ChainItem<XmlSignatureAnalysis> {

	private final CertificateWrapper certificate;

	public UniqueCertificateCheck(XmlSignatureAnalysis result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);

		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		return Utils.isStringNotBlank(certificate.getSerialNumber()) && Utils.isStringNotBlank(certificate.getCertificateDN());
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ART32_UNIQUE_CERT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ART32_UNIQUE_CERT_ANS;
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
