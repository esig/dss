package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.util.Set;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationCertHashMatchCheck extends ChainItem<XmlSubXCV> {

	private final CertificateWrapper certificate;

	public RevocationCertHashMatchCheck(XmlSubXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);

		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		Set<RevocationWrapper> revocationData = certificate.getRevocationData();
		if (Utils.isCollectionNotEmpty(revocationData)) {
			for (RevocationWrapper revocation : revocationData) {
				/*
				 * certHash extension can be present in an OCSP Response. If present, a digest match indicates the OCSP
				 * responder knows the certificate as we have it, and so also its revocation state
				 */
				if (revocation.isCertHashExtensionPresent() && !revocation.isCertHashExtensionMatch()) {
					return false;
				}
			}
		}
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_REVOC_CERT_HASH;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_REVOC_CERT_HASH_ANS;
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
