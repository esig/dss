package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationDataConsistant extends ChainItem<XmlVTS> {

	private final CertificateWrapper certificate;

	public RevocationDataConsistant(XmlVTS result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		RevocationWrapper revocationData = certificate.getRevocationData();

		Date certNotBefore = certificate.getNotBefore();
		Date certNotAfter = certificate.getNotAfter();
		Date thisUpdate = revocationData.getThisUpdate();

		Date expiredCertsOnCRL = revocationData.getExpiredCertsOnCRL();
		Date notAfterRevoc = thisUpdate;
		if (expiredCertsOnCRL != null) {
			notAfterRevoc = expiredCertsOnCRL;
		}

		Date archiveCutOff = revocationData.getArchiveCutOff();
		if (archiveCutOff != null) {
			notAfterRevoc = archiveCutOff;
		}

		return certNotBefore.before(thisUpdate) && (certNotAfter.compareTo(notAfterRevoc) >= 0);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.VTS_IRC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.VTS_IRC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.UNEXPECTED_ERROR;
	}

}
