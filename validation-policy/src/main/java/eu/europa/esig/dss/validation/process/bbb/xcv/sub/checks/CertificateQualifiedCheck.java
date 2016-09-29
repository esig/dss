package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateQualifiedCheck extends ChainItem<XmlSubXCV> {

	private final CertificateWrapper certificate;

	public CertificateQualifiedCheck(XmlSubXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {

		boolean isQCCompliant = QCStatementPolicyIdentifiers.isQCCompliant(certificate);
		boolean isQCP = CertificatePolicyIdentifiers.isQCP(certificate);
		boolean isQCPPlus = CertificatePolicyIdentifiers.isQCPPlus(certificate);

		// The content of a Trusted List through information provided in the Sie field of the applicable service entry
		List<String> qualifiers = certificate.getCertificateTSPServiceQualifiers();
		boolean isQcStatementInSIE = ServiceQualification.isQcStatement(qualifiers);
		boolean isNotQualifiedInSIE = ServiceQualification.isNotQualified(qualifiers);

		return ( ! isNotQualifiedInSIE ) && ( isQCCompliant || isQCP || isQCPPlus || isQcStatementInSIE );
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_CMDCIQC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_CMDCIQC_ANS;
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
