package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.MessageTag;

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
