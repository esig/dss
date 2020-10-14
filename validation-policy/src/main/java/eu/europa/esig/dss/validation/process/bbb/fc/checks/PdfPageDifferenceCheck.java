package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

public class PdfPageDifferenceCheck extends ChainItem<XmlFC> {

	private final SignatureWrapper signature;

	public PdfPageDifferenceCheck(I18nProvider i18nProvider, XmlFC result, SignatureWrapper signature, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.signature = signature;
	}

	@Override
	protected boolean process() {
		return Utils.isCollectionEmpty(signature.getPdfPageDifferenceConcernedPages());
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_FC_DSFREAP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_FC_DSFREAP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.FORMAT_FAILURE;
	}

}
