package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.util.List;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateIssuedToNaturalPersonCheck extends ChainItem<XmlSubXCV> {

	private final CertificateWrapper certificate;

	public CertificateIssuedToNaturalPersonCheck(XmlSubXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		List<String> qualifiers = certificate.getCertificateTSPServiceQualifiers();
		boolean tlNotLegal = !ServiceQualification.isQcForLegalPerson(qualifiers); // TODO improve

		boolean certPolicy = false;
		List<String> policyIds = certificate.getPolicyIds();
		if (CollectionUtils.isNotEmpty(policyIds)) {
			if (policyIds.contains(CertificatePolicyIdentifiers.QCP_NATURAL) || policyIds.contains(CertificatePolicyIdentifiers.QCP_NATURAL_QSCD)) {
				certPolicy = true;
			}
		}

		return tlNotLegal || certPolicy;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_CMDCIITNP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_CMDCIITNP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CHAIN_CONSTRAINTS_FAILURE;
	}

}
