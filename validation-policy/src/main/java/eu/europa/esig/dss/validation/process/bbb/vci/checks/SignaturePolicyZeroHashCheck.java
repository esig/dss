package eu.europa.esig.dss.validation.process.bbb.vci.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

public class SignaturePolicyZeroHashCheck extends ChainItem<XmlVCI> {

	private final SignatureWrapper signature;

	public SignaturePolicyZeroHashCheck(I18nProvider i18nProvider, XmlVCI result, SignatureWrapper signature, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.signature = signature;
	}

	@Override
	protected boolean process() {
		return signature.isPolicyZeroHash();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_VCI_IZHSP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_VCI_IZHSP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return null;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
