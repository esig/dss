package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.TSLConstant;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CertificateSupportedBySSCDCheck extends ChainItem<XmlSubXCV> {

	private final CertificateWrapper certificate;

	public CertificateSupportedBySSCDCheck(XmlSubXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		/**
		 * Mandates the end user certificate used in validating the signature to
		 * be supported by a secure signature creation device (SSCD) as defined
		 * in Directive 1999/93/EC [9]. This status is derived from: • QcSSCD
		 * extension being set in the signer's certificate in accordance with
		 * ETSI TS 101 862 [5];
		 */
		boolean qcSSCD = certificate.isCertificateQCSSCD();

		/**
		 * • QCP+ certificate policy OID being indicated in the signer's
		 * certificate policies extension (i.e. 0.4.0.1456.1.1);
		 */
		boolean qcpPlus = certificate.isCertificateQCPPlus();

		/**
		 * • The content of a Trusted service Status List;<br>
		 * • The content of a Trusted List through information provided in the
		 * Sie field of the applicable service entry; or
		 */

		List<String> qualifiers = certificate.getCertificateTSPServiceQualifiers();

		boolean sie = qualifiers.contains(TSLConstant.QC_WITH_SSCD) || qualifiers.contains(TSLConstant.QC_WITH_SSCD_119612);
		// TODO To be clarified with Olivier D.
		// || qualifiers.contains(QCSSCD_STATUS_AS_IN_CERT) || qualifiers
		// .contains(QCSSCD_STATUS_AS_IN_CERT_119612);

		if (!(qcSSCD || qcpPlus || sie)) {
			return false;
		}
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_CMDCISSCD;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_CMDCISSCD_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CHAIN_CONSTRAINTS_FAILURE;
	}

}
