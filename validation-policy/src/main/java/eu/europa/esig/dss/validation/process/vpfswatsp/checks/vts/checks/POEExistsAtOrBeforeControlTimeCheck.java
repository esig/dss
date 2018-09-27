package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.TimestampedObjectType;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class POEExistsAtOrBeforeControlTimeCheck extends ChainItem<XmlVTS> {

	private final TokenProxy token;
	private final TimestampedObjectType referenceCategory;
	private final Date controlTime;
	private final POEExtraction poe;

	public POEExistsAtOrBeforeControlTimeCheck(XmlVTS result, TokenProxy token, TimestampedObjectType referenceCategory, Date controlTime, POEExtraction poe,
			LevelConstraint constraint) {
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
	protected String getAdditionalInfo() {
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		Object[] params = new Object[] { sdf.format(controlTime) };
		return MessageFormat.format(AdditionalInfo.CONTROL_TIME, params);
	}

	@Override
	protected MessageTag getMessageTag() {
		if (TimestampedObjectType.CERTIFICATE.equals(referenceCategory)) {
			return MessageTag.PSV_ITPOCOBCT;
		} else if (TimestampedObjectType.REVOCATION.equals(referenceCategory)) {
			return MessageTag.PSV_ITPORDAOBCT;
		}
		throw new DSSException("Problem VTS");
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
