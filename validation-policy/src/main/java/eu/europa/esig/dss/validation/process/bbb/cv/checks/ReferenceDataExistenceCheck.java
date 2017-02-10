package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ReferenceDataExistenceCheck extends ChainItem<XmlCV> {

	private final TokenProxy token;

	public ReferenceDataExistenceCheck(XmlCV result, TokenProxy token, LevelConstraint constraint) {
		super(result, constraint);
		this.token = token;
	}

	@Override
	protected boolean process() {
		return token.isReferenceDataFound();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_CV_IRDOF;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_CV_IRDOF_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIGNED_DATA_NOT_FOUND;
	}

}
