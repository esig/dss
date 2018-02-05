package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.validation.ValidationTime;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class QualifiedCheck extends ChainItem<XmlValidationCertificateQualification> {

	private final QualifiedStatus qualifiedStatus;
	private final ValidationTime validationTime;

	public QualifiedCheck(XmlValidationCertificateQualification result, QualifiedStatus qualifiedStatus, ValidationTime validationTime, LevelConstraint constraint) {
		super(result, constraint);

		this.qualifiedStatus = qualifiedStatus;
		this.validationTime = validationTime;
	}

	@Override
	protected boolean process() {
		return QualifiedStatus.isQC(qualifiedStatus);
	}

	@Override
	protected MessageTag getMessageTag() {
		switch (validationTime) {
		case SIGNING_TIME:
			return MessageTag.QUAL_QC_AT_ST;
		case CERTIFICATE_ISSUANCE_TIME:
			return MessageTag.QUAL_QC_AT_CC;
		case VALIDATION_TIME:
			return MessageTag.QUAL_QC_AT_VT;
		default:
			throw new DSSException("Unsupported time " + validationTime);
		}
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		switch (validationTime) {
		case SIGNING_TIME:
			return MessageTag.QUAL_QC_AT_ST_ANS;
		case CERTIFICATE_ISSUANCE_TIME:
			return MessageTag.QUAL_QC_AT_CC_ANS;
		case VALIDATION_TIME:
			return MessageTag.QUAL_QC_AT_VT_ANS;
		default:
			throw new DSSException("Unsupported time " + validationTime);
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
