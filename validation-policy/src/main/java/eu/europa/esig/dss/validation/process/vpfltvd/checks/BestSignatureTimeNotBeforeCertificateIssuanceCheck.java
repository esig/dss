package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/*
 * If best-signature-time is before the issuance date of the signing certificate, the process shall return the
 * indication FAILED with the sub-indication NOT_YET_VALID. Otherwise, the process shall return the indication
 * INDETERMINATE with the sub-indication OUT_OF_BOUNDS_NO_POE.
 */
public class BestSignatureTimeNotBeforeCertificateIssuanceCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final Date bestSignatureTime;
	private final CertificateWrapper signingCertificate;

	public BestSignatureTimeNotBeforeCertificateIssuanceCheck(XmlValidationProcessLongTermData result, Date bestSignatureTime,
			CertificateWrapper signingCertificate, LevelConstraint constraint) {
		super(result, constraint);

		this.bestSignatureTime = bestSignatureTime;
		this.signingCertificate = signingCertificate;
	}

	@Override
	protected boolean process() {
		return !bestSignatureTime.before(signingCertificate.getNotBefore());
	}

	@Override
	protected String getAdditionalInfo() {
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		String bestSignatureTimeStr = bestSignatureTime == null ? " ? " : sdf.format(bestSignatureTime);
		return MessageFormat.format(AdditionalInfo.BEST_SIGNATURE_TIME, bestSignatureTimeStr);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.TSV_IBSTAIDOSC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.TSV_IBSTAIDOSC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NOT_YET_VALID;
	}

	@Override
	protected Indication getSuccessIndication() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getSuccessSubIndication() {
		return SubIndication.OUT_OF_BOUNDS_NO_POE;
	}

}
