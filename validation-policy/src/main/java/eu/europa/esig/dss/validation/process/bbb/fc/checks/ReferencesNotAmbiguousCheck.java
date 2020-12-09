package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the references are not ambiguous (only one document is retrieved)
 */
public class ReferencesNotAmbiguousCheck extends ChainItem<XmlFC> {

	/** The signature */
	private final SignatureWrapper signature;

	/** The ambiguous reference */
	private XmlDigestMatcher duplicatedReference;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlFC}
	 * @param signature {@link SignatureWrapper}
	 * @param constraint {@link LevelConstraint}
	 */
	public ReferencesNotAmbiguousCheck(I18nProvider i18nProvider, XmlFC result, SignatureWrapper signature,
			LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.signature = signature;
	}

	@Override
	protected boolean process() {
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			if (digestMatcher.isDuplicated()) {
				duplicatedReference = digestMatcher;
				return false;
			}
		}
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_FC_ISRIA;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_FC_ISRIA_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.FORMAT_FAILURE;
	}

	@Override
	protected String buildAdditionalInfo() {
		if (duplicatedReference != null) {
			String referenceName = Utils.isStringNotBlank(duplicatedReference.getName()) ? duplicatedReference.getName()
					: duplicatedReference.getType().name();
			return i18nProvider.getMessage(MessageTag.REFERENCE, referenceName);
		}
		return null;
	}

}
