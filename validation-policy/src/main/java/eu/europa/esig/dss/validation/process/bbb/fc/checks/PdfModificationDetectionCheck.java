package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import java.math.BigInteger;
import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

public class PdfModificationDetectionCheck extends ChainItem<XmlFC> {

	private final SignatureWrapper signature;

	public PdfModificationDetectionCheck(I18nProvider i18nProvider, XmlFC result, SignatureWrapper signature, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.signature = signature;
	}

	@Override
	protected boolean process() {
		return !signature.arePdfModificationsDetected();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_FC_IPMD;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_FC_IPMD_ANS;
	}
	
	@Override
	protected XmlName buildErrorMessage() {
		return buildXmlName(getErrorMessageTag(), getModificationsList());
	}
	
	private String getModificationsList() {
		StringBuilder stringBuilder = new StringBuilder();
		
		List<BigInteger> annotationsOverlapPages = signature.getPdfAnnotationsOverlapConcernedPages();
		if (Utils.isCollectionNotEmpty(annotationsOverlapPages)) {
			stringBuilder.append(i18nProvider.getMessage(MessageTag.BBB_FC_IPMD_AO_ANS, annotationsOverlapPages.toString()));
		}
		
		List<BigInteger> visualDifferenceConcernedPages = signature.getPdfVisualDifferenceConcernedPages();
		if (Utils.isCollectionNotEmpty(visualDifferenceConcernedPages)) {
			stringBuilder.append(i18nProvider.getMessage(MessageTag.BBB_FC_IPMD_VD_ANS, visualDifferenceConcernedPages.toString()));
		}
		
		return stringBuilder.toString();
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
