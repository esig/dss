package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.qualification.trust.AdditionalServiceInformation;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateAndServiceConsistencyCheck extends ChainItem<XmlValidationCertificateQualification> {

	private final CertificateWrapper signingCertificate;
	private final TrustedServiceWrapper trustedService;

	private MessageTag errorMessage;

	public CertificateAndServiceConsistencyCheck(XmlValidationCertificateQualification result, CertificateWrapper signingCertificate,
			TrustedServiceWrapper trustedService, LevelConstraint constraint) {
		super(result, constraint);

		this.signingCertificate = signingCertificate;
		this.trustedService = trustedService;
	}

	@Override
	protected boolean process() {
		if (trustedService != null) {

			boolean esign = QCTypeIdentifiers.isQCTypeEsign(signingCertificate);
			boolean eseal = QCTypeIdentifiers.isQCTypeEseal(signingCertificate);
			boolean web = QCTypeIdentifiers.isQCTypeWeb(signingCertificate);

			List<String> qualifiers = trustedService.getCapturedQualifiers();
			List<String> usageQualifiers = ServiceQualification.getUsageQualifiers(qualifiers);
			if (Utils.isCollectionEmpty(usageQualifiers)) {
				List<String> asis = trustedService.getAdditionalServiceInfos();
				if (esign && !AdditionalServiceInformation.isForeSignatures(asis)) {
					errorMessage = MessageTag.QUAL_TL_CERT_CONS_ANS3;
					return false;
				} else if (eseal && !AdditionalServiceInformation.isForeSeals(asis)) {
					errorMessage = MessageTag.QUAL_TL_CERT_CONS_ANS1;
					return false;
				} else if (web && !AdditionalServiceInformation.isForWebAuth(asis)) {
					errorMessage = MessageTag.QUAL_TL_CERT_CONS_ANS2;
					return false;
				}
			}
		}
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TL_CERT_CONS;
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
