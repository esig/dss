package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationSignatureQualification;
import eu.europa.esig.dss.validation.CertificateQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class QualifiedCertificateAtCertificateIssuanceCheck extends ChainItem<XmlValidationSignatureQualification> {

	private final CertificateQualification qualificationAtIssuance;

	public QualifiedCertificateAtCertificateIssuanceCheck(XmlValidationSignatureQualification result, CertificateQualification qualificationAtIssuance,
			LevelConstraint constraint) {
		super(result, constraint);

		this.qualificationAtIssuance = qualificationAtIssuance;
	}

	@Override
	protected boolean process() {
		return qualificationAtIssuance.isQc();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_QC_AT_CC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_QC_AT_CC_ANS;
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
