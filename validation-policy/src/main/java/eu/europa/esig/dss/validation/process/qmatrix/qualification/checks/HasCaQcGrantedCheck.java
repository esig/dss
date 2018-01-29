package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class HasCaQcGrantedCheck extends ChainItem<XmlValidationCertificateQualification> {

	private final List<TrustedServiceWrapper> caqcServicesAtTime;

	public HasCaQcGrantedCheck(XmlValidationCertificateQualification result, List<TrustedServiceWrapper> caqcServicesAtTime, LevelConstraint constraint) {
		super(result, constraint);

		this.caqcServicesAtTime = caqcServicesAtTime;
	}

	@Override
	protected boolean process() {
		return Utils.isCollectionNotEmpty(caqcServicesAtTime);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_HAS_CAQC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_HAS_CAQC_ANS;
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
