package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Checks if a signing certificate reference is present and valid
 */
public class SigningCertificateReferenceCheck extends ChainItem<XmlSAV> {

	/** The signature to check */
	private final SignatureWrapper signature;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlSAV}
	 * @param signature {@link SignatureWrapper}
	 * @param constraint {@link LevelConstraint}
	 */
	public SigningCertificateReferenceCheck(I18nProvider i18nProvider, XmlSAV result, SignatureWrapper signature,
											LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.signature = signature;
	}

	@Override
	protected boolean process() {
		FoundCertificatesProxy foundCertificates = signature.foundCertificates();
		
		// 1) Check orphan references presence
		List<CertificateRefWrapper> orphanSigningCertificateRefs = foundCertificates.getOrphanCertificateRefsByRefOrigin(
				CertificateRefOrigin.SIGNING_CERTIFICATE);
		if (Utils.isCollectionNotEmpty(orphanSigningCertificateRefs)) {
			// the provided reference does not match the provided certificate chain
			return false;
		}
		
		// 2) Check found references against the certificate chain
		List<RelatedCertificateWrapper> relatedSigningCertificates = foundCertificates.getRelatedCertificatesByRefOrigin(
				CertificateRefOrigin.SIGNING_CERTIFICATE);
		
		List<String> certificateChainIds = signature.getCertificateChain().stream().map(c -> c.getId()).collect(Collectors.toList());
		
		for (RelatedCertificateWrapper signingCertificate : relatedSigningCertificates) {
			if (!certificateChainIds.contains(signingCertificate.getId())) {
				// a certificate referenced by a SigningCertificate reference is not included into the certificate chain
				return false;
			}
		}
		
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_SAV_DSCACRCC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_SAV_DSCACRCC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}
	
}
