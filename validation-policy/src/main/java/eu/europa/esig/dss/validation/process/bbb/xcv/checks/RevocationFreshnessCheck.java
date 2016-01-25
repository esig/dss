package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.RuleUtils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.TimeConstraint;

public class RevocationFreshnessCheck extends ChainItem<XmlXCV> {

	private final CertificateWrapper certificate;
	private final TimeConstraint revocationFreshnessConstraints;
	private final Date currentTime;

	public RevocationFreshnessCheck(XmlXCV result, CertificateWrapper certificate, Date currentTime, TimeConstraint revocationFreshnessConstraints) {
		super(result, revocationFreshnessConstraints);
		this.certificate = certificate;
		this.revocationFreshnessConstraints = revocationFreshnessConstraints;
		this.currentTime = currentTime;
	}

	@Override
	protected boolean process() {
		RevocationWrapper revocationData = certificate.getRevocationData();
		if (revocationData != null && revocationData.getProductionDate() != null) {
			Date issuingTime = revocationData.getProductionDate();
			final long revocationDeltaTime = currentTime.getTime() - issuingTime.getTime();
			// TODO check 0day should not work
			if (revocationDeltaTime > RuleUtils.convertDuration(revocationFreshnessConstraints)) {
				return false;
			}
		}
		return true;

	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_IRIF;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_IRIF_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.TRY_LATER;
	}

}
