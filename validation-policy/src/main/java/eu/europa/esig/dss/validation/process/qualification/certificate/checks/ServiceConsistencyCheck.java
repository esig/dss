package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustedServiceChecker;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ServiceConsistencyCheck extends ChainItem<XmlValidationCertificateQualification> {

	private final TrustedServiceWrapper trustedService;

	private MessageTag errorMessage;

	public ServiceConsistencyCheck(XmlValidationCertificateQualification result, TrustedServiceWrapper trustedService, LevelConstraint constraint) {
		super(result, constraint);

		this.trustedService = trustedService;
	}

	@Override
	protected boolean process() {

		if (trustedService == null) {

			errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS0;
			return false;

		} else {

			if (!TrustedServiceChecker.isQCStatementConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS1;
				return false;
			}

			if (!TrustedServiceChecker.isLegalPersonConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS2;
				return false;
			}

			if (!TrustedServiceChecker.isQSCDConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS3;
				return false;
			}

			if (!TrustedServiceChecker.isUsageConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS4;
				return false;
			}

			if (!TrustedServiceChecker.isPreEIDASConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS5;
				return false;
			}

			if (!TrustedServiceChecker.isQualifierAndAdditionalServiceInfoConsistent(trustedService)) {
				errorMessage = MessageTag.QUAL_TL_SERV_CONS_ANS6;
				return false;
			}

			return true;
		}
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TL_SERV_CONS;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return errorMessage;
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
