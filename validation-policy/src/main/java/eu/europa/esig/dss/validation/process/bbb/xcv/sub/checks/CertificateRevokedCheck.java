package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.AdditionalInfo;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.x509.crl.CRLReasonEnum;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateRevokedCheck extends ChainItem<XmlSubXCV> {

	private final CertificateWrapper certificate;
	private final SubContext subContext;

	public CertificateRevokedCheck(XmlSubXCV result, CertificateWrapper certificate, LevelConstraint constraint, SubContext subContext) {
		super(result, constraint);
		this.certificate = certificate;
		this.subContext = subContext;
	}

	@Override
	protected boolean process() {
		RevocationWrapper revocationData = certificate.getLatestRevocationData();
		boolean isRevoked = (revocationData != null) && !revocationData.isStatus() && !CRLReasonEnum.certificateHold.name().equals(revocationData.getReason());
		if (!isRevoked) {
			return true;
		} else {
			return false;
		}
	}

	@Override
	protected String getAdditionalInfo() {
		RevocationWrapper revocationData = certificate.getLatestRevocationData();
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		String revocationDateStr = revocationData.getRevocationDate() == null ? " ? " : sdf.format(revocationData.getRevocationDate());
		Object[] params = new Object[] { revocationData.getReason(), revocationDateStr };
		return MessageFormat.format(AdditionalInfo.REVOCATION, params);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_ISCR;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_ISCR_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		if (SubContext.SIGNING_CERT.equals(subContext)) {
			return SubIndication.REVOKED_NO_POE;
		} else {
			return SubIndication.REVOKED_CA_NO_POE;
		}
	}

}
