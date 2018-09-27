package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ReferenceDataExistenceCheck extends ChainItem<XmlCV> {

	private final XmlDigestMatcher digestMatcher;

	public ReferenceDataExistenceCheck(XmlCV result, XmlDigestMatcher digestMatcher, LevelConstraint constraint) {
		super(result, constraint);
		this.digestMatcher = digestMatcher;
	}

	@Override
	protected boolean process() {
		return digestMatcher.isDataFound();
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

	@Override
	protected String getAdditionalInfo() {
		if (Utils.isStringNotBlank(digestMatcher.getName())) {
			return "Reference : " + digestMatcher.getName();
		} else {
			return digestMatcher.getType().name();
		}
	}

}
