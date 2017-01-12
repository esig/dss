package eu.europa.esig.dss.validation.process.art32.qualification.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateNotRevokedAtSigningTimeCheck extends ChainItem<XmlSignatureAnalysis> {

	private final CertificateWrapper certificate;
	private final Date signingTime;

	public CertificateNotRevokedAtSigningTimeCheck(XmlSignatureAnalysis result, CertificateWrapper certificate, Date signingTime, LevelConstraint constraint) {
		super(result, constraint);

		this.certificate = certificate;
		this.signingTime = signingTime;
	}

	@Override
	protected boolean process() {
		RevocationWrapper revocationData = certificate.getLatestRevocationData();
		if (revocationData != null && revocationData.getRevocationDate() != null) {
			return revocationData.getRevocationDate().compareTo(signingTime) > 0;
		}
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ART32_CERT_REVOKED_AT_ST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ART32_CERT_REVOKED_AT_ST_ANS;
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
