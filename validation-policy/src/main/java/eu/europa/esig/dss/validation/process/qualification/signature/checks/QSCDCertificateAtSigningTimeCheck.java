package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationSignatureQualification;
import eu.europa.esig.dss.validation.CertificateQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class QSCDCertificateAtSigningTimeCheck extends ChainItem<XmlValidationSignatureQualification> {

	private final CertificateQualification certificateQualification;

	public QSCDCertificateAtSigningTimeCheck(XmlValidationSignatureQualification result, CertificateQualification certificateQualification,
			LevelConstraint constraint) {
		super(result, constraint);

		this.certificateQualification = certificateQualification;
	}

	@Override
	protected boolean process() {
		return certificateQualification.isQscd();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_QSCD_AT_ST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_QSCD_AT_ST_ANS;
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
