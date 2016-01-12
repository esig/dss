package eu.europa.esig.dss.EN319102.bbb.rfc.checks;

import java.util.Date;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.policy.RuleUtils;
import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.RevocationWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.TimeConstraint;

public class RevocationDataFreshCheck extends ChainItem<XmlRFC> {

	private final CertificateWrapper certificate;
	private final Date validationDate;
	private final TimeConstraint timeConstraint;

	public RevocationDataFreshCheck(XmlRFC result, CertificateWrapper certificate, Date validationDate, TimeConstraint constraint) {
		super(result, constraint);

		this.certificate = certificate;
		this.validationDate = validationDate;
		this.timeConstraint = constraint;
	}

	@Override
	protected boolean process() {
		RevocationWrapper revocationData = certificate.getRevocationData();
		if (revocationData != null) {
			long maxFreshness = getMaxFreshness();
			long validationDateTime = validationDate.getTime();
			long limit = validationDateTime - maxFreshness;

			Date productionDate = revocationData.getProductionDate();
			return productionDate != null && productionDate.after(new Date(limit));
		}
		return false;
	}

	private long getMaxFreshness() {
		long maxFreshness = RuleUtils.convertDuration(timeConstraint);
		if (maxFreshness == 0) {
			RevocationWrapper revocationData = certificate.getRevocationData();
			maxFreshness = diff(revocationData.getNextUpdate(), revocationData.getThisUpdate());
		}
		return maxFreshness;
	}

	private long diff(Date nextUpdate, Date thisUpdate) {
		long nextUpdateTime = nextUpdate == null ? 0 : nextUpdate.getTime();
		long thisUpdateTime = thisUpdate == null ? 0 : thisUpdate.getTime();
		return nextUpdateTime - thisUpdateTime;
	}

	@Override
	protected MessageTag getMessageTag() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
