package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class POEExistsAtOrBeforeControlTimeCheck extends ChainItem<XmlVTS> {

	private final TokenProxy token;
	private final Context context;
	private final Date controlTime;
	private final POEExtraction poe;

	public POEExistsAtOrBeforeControlTimeCheck(XmlVTS result, TokenProxy token, Context context, Date controlTime, POEExtraction poe,
			LevelConstraint constraint) {
		super(result, constraint);

		this.token = token;
		this.context = context;
		this.controlTime = controlTime;
		this.poe = poe;
	}

	@Override
	protected boolean process() {
		return poe.isPOEExists(token.getId(), controlTime);
	}

	@Override
	protected MessageTag getMessageTag() {
		if (Context.SIGNATURE.equals(context)) {
			return MessageTag.PSV_ITPOSVAOBCT;
		} else {
			return MessageTag.PSV_ITPORDAOBCT;
		}
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PSV_ITPOSVAOBCT_ANS;
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
