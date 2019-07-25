package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.MessageTag;

public class ManifestEntryIntactCheck extends ReferenceDataIntactCheck {

	public ManifestEntryIntactCheck(XmlCV result, XmlDigestMatcher digestMatcher, LevelConstraint constraint) {
		super(result, digestMatcher, constraint);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_CV_IMEOI;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_CV_IMEOI_ANS;
	}
}
