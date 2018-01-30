package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationSignatureQualification;
import eu.europa.esig.dss.validation.CertificateQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class QualifiedCertificateAtSigningTimeCheck extends ChainItem<XmlValidationSignatureQualification> {

	private final CertificateQualification qualificationAtSigningTime;

	public QualifiedCertificateAtSigningTimeCheck(XmlValidationSignatureQualification result, CertificateQualification qualificationAtSigningTime,
			LevelConstraint constraint) {
		super(result, constraint);

		this.qualificationAtSigningTime = qualificationAtSigningTime;
	}

	@Override
	protected boolean process() {
		return qualificationAtSigningTime.isQc();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_QC_AT_ST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_QC_AT_ST_ANS;
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
