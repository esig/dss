package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SatisfyingRevocationDataExistsCheck extends ChainItem<XmlVTS> {

	private final RevocationWrapper revocationData;

	public SatisfyingRevocationDataExistsCheck(XmlVTS result, RevocationWrapper revocationData, LevelConstraint constraint) {
		super(result, constraint);

		this.revocationData = revocationData;
	}

	@Override
	protected boolean process() {
		return revocationData != null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_VTS_IRDPFC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_VTS_IRDPFC_ANS;
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
