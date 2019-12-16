package eu.europa.esig.dss.validation.process;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

public class ValidationProcessUtils {
	
	/**
	 * Returns a latest consistant revocation data to be known to have a revocation status for the given certificate
	 * 
	 * @param certificate {@link CertificateWrapper} to get latest compliant revocation for
	 * @return latest available known {@link CertificateRevocationWrapper}
	 */
	public static CertificateRevocationWrapper getLatestKnownRevocationData(CertificateWrapper certificate, ValidationPolicy validationPolicy) {
		return getLatestKnownRevocationData(new ArrayList<String>(), certificate, validationPolicy);
	}
	
	private static CertificateRevocationWrapper getLatestKnownRevocationData(List<String> checkedTokenIds, 
			CertificateWrapper certificate, ValidationPolicy validationPolicy) {
		CertificateRevocationWrapper latestCompliantRevocation = null;
		List<CertificateRevocationWrapper> revocations = certificate.getCertificateRevocationData();
		for (CertificateRevocationWrapper revocation : revocations) {
			if ((latestCompliantRevocation == null || revocation.getProductionDate().after(latestCompliantRevocation.getProductionDate()))
					&& isConsistant(certificate, revocation) && isAcceptable(checkedTokenIds, revocation, validationPolicy)) {
				latestCompliantRevocation = revocation;
			}
		}
		return latestCompliantRevocation;
	}

	private static boolean isConsistant(CertificateWrapper certificate, RevocationWrapper revocationData) {
		Date certNotBefore = certificate.getNotBefore();
		Date certNotAfter = certificate.getNotAfter();
		Date thisUpdate = revocationData.getThisUpdate();

		Date notAfterRevoc = thisUpdate;

		/*
		 * If a CRL contains the extension expiredCertsOnCRL defined in [i.12], it shall prevail over the TL
		 * extension value but only for that specific CRL.
		 */
		Date expiredCertsOnCRL = revocationData.getExpiredCertsOnCRL();
		if (expiredCertsOnCRL != null) {
			notAfterRevoc = expiredCertsOnCRL;
		}

		/*
		 * If an OCSP response contains the extension ArchiveCutoff defined in section 4.4.4 of
		 * IETF RFC 6960 [i.11], it shall prevail over the TL extension value but only for that specific OCSP
		 * response.
		 */
		Date archiveCutOff = revocationData.getArchiveCutOff();
		if (archiveCutOff != null) {
			notAfterRevoc = archiveCutOff;
		}

		/* expiredCertsRevocationInfo Extension from TL */
		if (expiredCertsOnCRL != null || archiveCutOff != null) {
			CertificateWrapper revocCert = revocationData.getSigningCertificate();
			if (revocCert != null) {
				Date expiredCertsRevocationInfo = revocCert.getCertificateTSPServiceExpiredCertsRevocationInfo();
				if (expiredCertsRevocationInfo != null && expiredCertsRevocationInfo.before(notAfterRevoc)) {
					notAfterRevoc = expiredCertsRevocationInfo;
				}
			}
		}

		/*
		 * certHash extension can be present in an OCSP Response. If present, a digest match indicates the OCSP
		 * responder knows the certificate as we have it, and so also its revocation state
		 */
		boolean certHashOK = revocationData.isCertHashExtensionPresent() && revocationData.isCertHashExtensionMatch();

		return thisUpdate != null && certNotBefore.before(thisUpdate) && ((certNotAfter.compareTo(notAfterRevoc) >= 0) || certHashOK);
	}

	private static boolean isAcceptable(List<String> checkedTokenIds, CertificateRevocationWrapper revocation, ValidationPolicy validationPolicy) {
		LevelConstraint revocationSignatureIntactConstraint = validationPolicy.getSignatureIntactConstraint(Context.REVOCATION);
		if (isFailLevel(revocationSignatureIntactConstraint) && !revocation.isSignatureIntact()) {
			return false;
		}
		for (CertificateWrapper revocationCertificate : revocation.getCertificateChain()) {
			// break in case of trusted cert and in infinite loop
			if (revocationCertificate.isTrusted()) {
				break;
			}
			if (checkedTokenIds.contains(revocationCertificate.getId())) {
				continue;
			}
			checkedTokenIds.add(revocationCertificate.getId());
			
			LevelConstraint certificateSignatureIntactConstraint = validationPolicy.getSignatureIntactConstraint(Context.CERTIFICATE);
			if (isFailLevel(certificateSignatureIntactConstraint) && !revocationCertificate.isSignatureIntact()) {
				return false;
			}
			
			if (revocationCertificate.isIdPkixOcspNoCheck()) {
				continue;
			}
			
			SubContext subContext = revocation.getSigningCertificate().getId().equals(revocationCertificate.getId()) ? 
					SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
			LevelConstraint revocationDataAvailableConstraint = validationPolicy.getRevocationDataAvailableConstraint(Context.REVOCATION, subContext);
			if (isFailLevel(revocationDataAvailableConstraint) && getLatestKnownRevocationData(checkedTokenIds, revocationCertificate, validationPolicy) == null) {
				return false;
			}
			
		}
		return true;
	}
	
	private static boolean isFailLevel(LevelConstraint levelConstraint) {
		return levelConstraint != null && Level.FAIL.equals(levelConstraint.getLevel());
	}

}
