package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.QualificationTime;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class QualifiedCheck extends ChainItem<XmlValidationCertificateQualification> {

	private final QualifiedStatus qualifiedStatus;
	private final QualificationTime time;

	public QualifiedCheck(XmlValidationCertificateQualification result, QualifiedStatus qualifiedStatus, QualificationTime time, LevelConstraint constraint) {
		super(result, constraint);

		this.qualifiedStatus = qualifiedStatus;
		this.time = time;
	}

	@Override
	protected boolean process() {
		return QualifiedStatus.isQC(qualifiedStatus);
	}

	@Override
	protected MessageTag getMessageTag() {
		switch (time) {
		case SIGNING_TIME:
			return MessageTag.QUAL_QC_AT_ST;
		case CERTIFICATE_ISSUANCE_TIME:
			return MessageTag.QUAL_QC_AT_CC;
		case VALIDATION_TIME:
			return MessageTag.QUAL_QC_AT_VT;
		default:
			throw new DSSException("Unsupported time " + time);
		}
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		switch (time) {
		case SIGNING_TIME:
			return MessageTag.QUAL_QC_AT_ST_ANS;
		case CERTIFICATE_ISSUANCE_TIME:
			return MessageTag.QUAL_QC_AT_CC_ANS;
		case VALIDATION_TIME:
			return MessageTag.QUAL_QC_AT_VT_ANS;
		default:
			throw new DSSException("Unsupported time " + time);
		}
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
