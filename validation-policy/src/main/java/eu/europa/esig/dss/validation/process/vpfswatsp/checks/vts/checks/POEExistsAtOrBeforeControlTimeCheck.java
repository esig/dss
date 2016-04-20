package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import java.util.Date;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.TimestampReferenceCategory;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class POEExistsAtOrBeforeControlTimeCheck extends ChainItem<XmlVTS> {

	private final TokenProxy token;
	private final TimestampReferenceCategory referenceCategory;
	private final Date controlTime;
	private final POEExtraction poe;

	public POEExistsAtOrBeforeControlTimeCheck(XmlVTS result, TokenProxy token, TimestampReferenceCategory referenceCategory, Date controlTime,
			POEExtraction poe, LevelConstraint constraint) {
		super(result, constraint);

		this.token = token;
		this.referenceCategory = referenceCategory;
		this.controlTime = controlTime;
		this.poe = poe;
	}

	@Override
	protected boolean process() {
		return poe.isPOEExists(token.getId(), controlTime);
	}

	@Override
	protected MessageTag getMessageTag() {
		if (TimestampReferenceCategory.CERTIFICATE.equals(referenceCategory)) {
			return MessageTag.PSV_ITPOCOBCT;
		} else if (TimestampReferenceCategory.REVOCATION.equals(referenceCategory)) {
			return MessageTag.PSV_ITPORDAOBCT;
		}
		throw new DSSException("Probleme VTS");
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PSV_ITPOOBCT_ANS;
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
