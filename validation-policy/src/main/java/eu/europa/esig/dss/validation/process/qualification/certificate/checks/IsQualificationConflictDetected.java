package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import java.util.Set;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

public class IsQualificationConflictDetected extends ChainItem<XmlValidationCertificateQualification> {

	private final Set<CertificateQualification> certificateQualificationsAtTime;

	public IsQualificationConflictDetected(I18nProvider i18nProvider,
			XmlValidationCertificateQualification result,
			Set<CertificateQualification> certificateQualificationsAtTime, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.certificateQualificationsAtTime = certificateQualificationsAtTime;
	}

	@Override
	protected boolean process() {
		return Utils.collectionSize(certificateQualificationsAtTime) == 1;
	}

	@Override
	protected MessageTag getAdditionalInfo() {
		if (Utils.collectionSize(certificateQualificationsAtTime) > 1) {
			return MessageTag.RESULTS.setArgs(certificateQualificationsAtTime.toString());
		}
		return null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_HAS_CONF;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_HAS_CONF_ANS;
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
