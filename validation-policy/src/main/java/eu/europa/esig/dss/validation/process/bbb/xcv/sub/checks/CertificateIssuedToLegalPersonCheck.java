package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateIssuedToLegalPersonCheck extends ChainItem<XmlSubXCV> {

	private final CertificateWrapper certificate;

	public CertificateIssuedToLegalPersonCheck(XmlSubXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		List<String> qualifiers = certificate.getCertificateTSPServiceQualifiers();

		/**
		 * Mandates the signer's certificate used in validating the signature to
		 * be issued by a certificate authority issuing certificate as having
		 * been issued to a legal person.
		 */
		boolean tlQualifier = ServiceQualification.isQcForLegalPerson(qualifiers);
		boolean certPolicy = CertificatePolicyIdentifiers.isLegal(certificate);

		return tlQualifier || certPolicy;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_CMDCIITLP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_CMDCIITLP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CHAIN_CONSTRAINTS_FAILURE;
	}

}
