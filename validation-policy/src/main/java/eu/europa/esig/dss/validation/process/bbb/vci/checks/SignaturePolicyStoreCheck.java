package eu.europa.esig.dss.validation.process.bbb.vci.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if a SignaturePolicyStore is present
 */
public class SignaturePolicyStoreCheck extends ChainItem<XmlVCI> {

	/** The signature to check */
	private final SignatureWrapper signature;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlVCI}
	 * @param signature {@link SignatureWrapper}
	 * @param constraint {@link LevelConstraint}
	 */
	public SignaturePolicyStoreCheck(I18nProvider i18nProvider, XmlVCI result, SignatureWrapper signature, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.signature = signature;
	}

	@Override
	protected boolean process() {
		return signature.isPolicyStorePresent();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_VCI_ISPSUPP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_VCI_ISPSUPP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE;
	}

}
