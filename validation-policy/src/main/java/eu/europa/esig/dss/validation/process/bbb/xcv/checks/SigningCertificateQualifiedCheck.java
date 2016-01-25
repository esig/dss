package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.TSLConstant;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SigningCertificateQualifiedCheck extends ChainItem<XmlXCV> {

	private final CertificateWrapper certificate;

	public SigningCertificateQualifiedCheck(XmlXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		/**
		 * Mandates the signer's certificate used in validating the signature to be a qualified certificate as defined
		 * in
		 * Directive 1999/93/EC [9]. This status can be derived from:
		 */

		/**
		 * • QcCompliance extension being set in the signer's certificate in accordance with TS 101 862 [5];
		 */

		/**
		 * • QCP+ or QCP certificate policy OID being indicated in the signer's certificate policies extension (i.e.
		 * 0.4.0.1456.1.1 or 0.4.0.1456.1.2);
		 */

		boolean isQCC = certificate.isCertificateQCC();
		boolean isQCP = certificate.isCertificateQCP();
		boolean isQCPPlus = certificate.isCertificateQCPPlus();

		/**
		 * • The content of a Trusted service Status List;<br>
		 * • The content of a Trusted List through information provided in the Sie field of the applicable service
		 * entry;
		 */
		List<String> qualifiers = certificate.getCertificateTSPServiceQualifiers();
		boolean isSIE = qualifiers.contains(TSLConstant.QC_STATEMENT) || qualifiers.contains(TSLConstant.QC_STATEMENT_119612);

		return isQCC || isQCP || isQCPPlus || isSIE;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_CMDCIQC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_CMDCIQC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CHAIN_CONSTRAINTS_FAILURE;
	}

}
