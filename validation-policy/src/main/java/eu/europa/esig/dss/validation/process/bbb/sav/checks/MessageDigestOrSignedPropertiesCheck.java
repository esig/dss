package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class MessageDigestOrSignedPropertiesCheck extends ChainItem<XmlSAV> {

	private final SignatureWrapper signature;

	public MessageDigestOrSignedPropertiesCheck(XmlSAV result, SignatureWrapper signature, LevelConstraint constraint) {
		super(result, constraint);
		this.signature = signature;
	}

	@Override
	protected boolean process() {
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		if (Utils.isCollectionNotEmpty(digestMatchers)) {
			for (XmlDigestMatcher digestMatcher : digestMatchers) {
				// for CAdES and PAdES
				if (DigestMatcherType.MESSAGE_DIGEST.equals(digestMatcher.getType()) || 
						// for XAdES
						DigestMatcherType.SIGNED_PROPERTIES.equals(digestMatcher.getType())) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_SAV_ISQPMDOSPP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_SAV_ISQPMDOSPP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
