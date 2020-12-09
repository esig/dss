package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

import java.util.List;

/**
 * Check if DigestAlgorithm is acceptable
 */
public class DigestAlgorithmReliableCheck extends AbstractCryptographicCheck {

	/** The algorithm to check */
	private final DigestAlgorithm digestAlgo;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param digestAlgo {@link DigestAlgorithm}
	 * @param result {@link XmlCC}
	 * @param position {@link MessageTag}
	 * @param constraintWrapper {@link CryptographicConstraintWrapper}
	 */
	protected DigestAlgorithmReliableCheck(I18nProvider i18nProvider, DigestAlgorithm digestAlgo, XmlCC result,
										   MessageTag position, CryptographicConstraintWrapper constraintWrapper) {
		super(i18nProvider, result, position, constraintWrapper);
		this.digestAlgo = digestAlgo;
	}

	@Override
	protected boolean process() {
		String algoToFind = digestAlgo == null ? Utils.EMPTY_STRING : digestAlgo.getName();
		List<String> supportedDigestAlgorithms = constraintWrapper.getSupportedDigestAlgorithms();
		if (Utils.isCollectionNotEmpty(supportedDigestAlgorithms)) {
			if (!supportedDigestAlgorithms.contains(algoToFind)) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	protected XmlName buildConstraintMessage() {
		return buildXmlName(MessageTag.ASCCM_DAA, digestAlgo);
	}
	
	@Override
	protected XmlName buildErrorMessage() {
		return buildXmlName(MessageTag.ASCCM_DAA_ANS, digestAlgo, position);
	}

}
