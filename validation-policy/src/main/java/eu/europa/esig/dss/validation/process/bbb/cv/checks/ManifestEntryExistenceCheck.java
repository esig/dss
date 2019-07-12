package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ManifestEntryExistenceCheck extends ReferenceDataExistenceCheck {

	public ManifestEntryExistenceCheck(XmlCV result, XmlDigestMatcher digestMatcher, LevelConstraint constraint) {
		super(result, digestMatcher, constraint);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_CV_IMEOF;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_CV_IMEOF_ANS;
	}

}
