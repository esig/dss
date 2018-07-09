package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateIssuedByConsistentTrustServiceCheck extends ChainItem<XmlValidationCertificateQualification> {

	private final List<TrustedServiceWrapper> trustServicesAtTime;

	public CertificateIssuedByConsistentTrustServiceCheck(XmlValidationCertificateQualification result,
			List<TrustedServiceWrapper> trustServicesAtTime, LevelConstraint constraint) {
		super(result, constraint);

		this.trustServicesAtTime = trustServicesAtTime;
	}

	@Override
	protected boolean process() {
		return Utils.isCollectionNotEmpty(trustServicesAtTime);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_HAS_CONSISTENT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_HAS_CONSISTENT_ANS;
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
