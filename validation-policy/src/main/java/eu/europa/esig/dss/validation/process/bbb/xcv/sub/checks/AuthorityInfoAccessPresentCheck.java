package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class AuthorityInfoAccessPresentCheck extends ChainItem<XmlSubXCV> {

	private final CertificateWrapper certificate;

	public AuthorityInfoAccessPresentCheck(XmlSubXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);

		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		return Utils.isCollectionNotEmpty(certificate.getAuthorityInformationAccessUrls());
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_AIA_PRES;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_AIA_PRES_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
