package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class IssuanceDateBeforeControlTime extends ChainItem<XmlVTS> {

	private final RevocationWrapper revocationData;
	private final Date controlTime;

	public IssuanceDateBeforeControlTime(XmlVTS result, RevocationWrapper revocationData, Date controlTime, LevelConstraint constraint) {
		super(result, constraint);

		this.revocationData = revocationData;
		this.controlTime = controlTime;
	}

	@Override
	protected boolean process() {
		Date issuanceDate = revocationData.getProductionDate();
		return issuanceDate.before(controlTime);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.VTS_ICTBRD;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.VTS_ICTBRD_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_POE;
	}

}
