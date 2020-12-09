package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

/**
 * The abstract cryptographic check
 */
public abstract class AbstractCryptographicCheck extends ChainItem<XmlCC> {

	/** The validating constraint position */
	protected final MessageTag position;

	/** The constraint */
	protected final CryptographicConstraintWrapper constraintWrapper;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlCC}
	 * @param position {@link MessageTag}
	 * @param constraintWrapper {@link CryptographicConstraintWrapper}
	 */
	protected AbstractCryptographicCheck(I18nProvider i18nProvider, XmlCC result, MessageTag position,
										 CryptographicConstraintWrapper constraintWrapper) {
		super(i18nProvider, result, constraintWrapper.getConstraint());
		this.position = position;
		this.constraintWrapper = constraintWrapper;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE;
	}

}
