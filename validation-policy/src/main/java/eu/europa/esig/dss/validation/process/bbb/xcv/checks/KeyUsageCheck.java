package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.wrappers.CertificateWrapper;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class KeyUsageCheck extends ChainItem<XmlXCV> {

	private final CertificateWrapper certificate;
	private final MultiValuesConstraint constraint;

	public KeyUsageCheck(XmlXCV result, CertificateWrapper certificate, MultiValuesConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
		this.constraint = constraint;
	}

	@Override
	protected boolean process() {
		if (CollectionUtils.isNotEmpty(constraint.getId())) {
			return constraint.getId().containsAll(certificate.getKeyUsages());
		}
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_ISCGKU;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_ISCGKU_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
