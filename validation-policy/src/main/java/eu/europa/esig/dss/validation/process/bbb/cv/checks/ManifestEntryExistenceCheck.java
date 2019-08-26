package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.IMessageTag;
import eu.europa.esig.dss.validation.process.MessageTag;

public class ManifestEntryExistenceCheck extends ChainItem<XmlCV> {

	private final List<XmlDigestMatcher> digestMatchers;

	public ManifestEntryExistenceCheck(XmlCV result, List<XmlDigestMatcher> digestMatchers, LevelConstraint constraint) {
		super(result, constraint);
		this.digestMatchers = digestMatchers;
	}

	@Override
	protected boolean process() {
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			if (DigestMatcherType.MANIFEST_ENTRY.equals(xmlDigestMatcher.getType())) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected IMessageTag getMessageTag() {
		return MessageTag.BBB_CV_ISMEC;
	}

	@Override
	protected IMessageTag getErrorMessageTag() {
		return MessageTag.BBB_CV_ISMEC_ANS;
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
