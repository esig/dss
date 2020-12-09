package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the certificate in question is not present in the OCSP's certificate chain
 */
public class SelfIssuedOCSPCheck extends ChainItem<XmlRAC> {

	/** The certificate in question */
	private final CertificateWrapper certificateWrapper;

	/** Revocation data to check */
	private final RevocationWrapper revocationData;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param certificateWrapper {@link CertificateWrapper}
	 * @param revocationData {@link RevocationWrapper}
	 * @param constraint {@link LevelConstraint}
	 */
	public SelfIssuedOCSPCheck(I18nProvider i18nProvider, XmlRAC result, CertificateWrapper certificateWrapper,
			RevocationWrapper revocationData, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.certificateWrapper = certificateWrapper;
		this.revocationData = revocationData;
	}

	@Override
	protected boolean process() {
		for (CertificateWrapper certificate : revocationData.getCertificateChain()) {
			if (certificateWrapper.getId().equals(certificate.getId())) {
				return false;
			}
		}
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_REVOC_SELF_ISSUED_OCSP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_REVOC_SELF_ISSUED_OCSP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.TRY_LATER;
	}

}
