package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.wrappers.CertificateWrapper;
import eu.europa.esig.dss.validation.wrappers.RevocationWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class IntermediateCertificateRevokedCheck extends ChainItem<XmlXCV> {

	private final CertificateWrapper certificate;

	public IntermediateCertificateRevokedCheck(XmlXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		RevocationWrapper revocationData = certificate.getRevocationData();
		return (revocationData != null) && !revocationData.isStatus();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_IICR;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_IICR_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.REVOKED_CA_NO_POE;
	}

}
