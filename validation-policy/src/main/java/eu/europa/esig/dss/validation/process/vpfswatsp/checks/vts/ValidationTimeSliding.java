package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.TimestampReferenceCategory;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.RevocationFreshnessChecker;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.POEExistsAtOrBeforeControlTimeCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.SatisfyingRevocationDataExistsCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

public class ValidationTimeSliding extends Chain<XmlVTS> {

	private final DiagnosticData diagnosticData;
	private final TokenProxy token;
	private final Date currentTime;

	private final Context context;

	private final POEExtraction poe;
	private final ValidationPolicy policy;

	private Date controlTime;

	public ValidationTimeSliding(DiagnosticData diagnosticData, TokenProxy token, Date currentTime, Context context, POEExtraction poe,
			ValidationPolicy policy) {
		super(new XmlVTS());

		this.diagnosticData = diagnosticData;
		this.token = token;
		this.currentTime = currentTime;

		this.context = context;

		this.poe = poe;
		this.policy = policy;
	}

	@Override
	protected void initChain() {

		/*
		 * 5.6.2.2.4 Processing
		 * 
		 * 1) The building block shall initialize control-time to the current
		 * date/time.
		 * 
		 * NOTE 1: Control-time is an internal variable that is used within the
		 * algorithms and not part of the core results of the validation
		 * process.
		 */
		controlTime = currentTime;

		List<String> certificateChainIds = token.getCertificateChainIds();
		if (Utils.isCollectionNotEmpty(certificateChainIds)) {

			/*
			 * 2) For each certificate in the chain starting from the first
			 * certificate (the certificate issued by the trust anchor):
			 */
			Collections.reverse(certificateChainIds); // trusted_list -> ... ->
														// signature

			for (String certificateId : certificateChainIds) {
				CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certificateId);
				if (certificate.isTrusted()) {
					continue;
				}

				/*
				 * a) The building block shall find revocation status
				 * information satisfying the following:
				 * 
				 * - The revocation status information is consistent with the
				 * rules conditioning its use to check the revocation status of
				 * the considered certificate. In the case of a CRL, it shall
				 * satisfy the checks specified in IETF RFC 5280 [1] clause 6.3;
				 * and
				 * 
				 * - The issuance date of the revocation status information is
				 * before control-time. If more than one revocation status is
				 * found, the building block shall consider the most recent one
				 * and shall go to the next step.
				 * 
				 * If more than one revocation status is found, the building block shall consider the most recent one
				 * and shall go to the next step.
				 * 
				 * If there is no such information, The building block shall
				 * return the indication INDETERMINATE with the sub-indication
				 * NO_POE.
				 */
				RevocationWrapper latestCompliantRevocation = null;
				Set<RevocationWrapper> revocations = certificate.getRevocationData();
				for (RevocationWrapper revocation : revocations) {
					if ((latestCompliantRevocation == null || revocation.getProductionDate().after(latestCompliantRevocation.getProductionDate()))
							&& isConsistant(certificate, revocation) && isIssuanceBeforeControlTime(revocation)) {
						latestCompliantRevocation = revocation;
					}
				}

				ChainItem<XmlVTS> item = satisfyingRevocationDataExists(latestCompliantRevocation);
				if (firstItem == null) {
					firstItem = item;
				}

				/*
				 * b) If the set of POEs contains a proof of existence
				 * of the certificate and the revocation status
				 * information at (or before) control-time, the building
				 * block shall go to step c).
				 * 
				 * Otherwise, the building block shall return the
				 * indication INDETERMINATE with the sub-indication
				 * NO_POE.
				 */
				item = item.setNextItem(poeExistsAtOrBeforeControlTime(certificate, TimestampReferenceCategory.CERTIFICATE, controlTime));

				item = item.setNextItem(poeExistsAtOrBeforeControlTime(latestCompliantRevocation, TimestampReferenceCategory.REVOCATION, controlTime));

				/*
				 * c) The update of the value of control-time is as
				 * follows:
				 * 
				 * - If the certificate is marked as revoked in the
				 * revocation status information, the building block
				 * shall set control-time to the revocation time.
				 * 
				 * - If the certificate is not marked as revoked, the
				 * building block shall run the Revocation Freshness
				 * Checker with the used revocation information status,
				 * the certificate for which the revocation status is
				 * being checked and the control-time. If it returns
				 * FAILED, the building block shall set control-time to
				 * the issuance time of the revocation status
				 * information.
				 * 
				 * Otherwise, the building block shall not change the
				 * value of control-time.
				 */
				if (latestCompliantRevocation != null) {
					if (certificate.isRevoked()) {
						controlTime = latestCompliantRevocation.getRevocationDate();
					} else if (!isFresh(latestCompliantRevocation, controlTime)) {
						controlTime = latestCompliantRevocation.getProductionDate();
					}
				}

				/*
				 * d) The building block shall apply the cryptographic
				 * constraints to the certificate and the revocation
				 * status information against the control-time. If the
				 * certificate (or the revocation status information)
				 * does not match these constraints, the building block
				 * shall set control-time to the lowest time up to which
				 * the listed algorithms were considered reliable.
				 */
				item = item.setNextItem(cryptographicCheck(certificate, controlTime));

				item = item.setNextItem(cryptographicCheck(latestCompliantRevocation, controlTime));

			}
		}
	}

	@Override
	protected void addAdditionalInfo() {
		result.setControlTime(controlTime);
	}

	private boolean isFresh(RevocationWrapper revocationData, Date controlTime) {
		// TODO SubContext ??
		RevocationFreshnessChecker rfc = new RevocationFreshnessChecker(revocationData, controlTime, context, SubContext.SIGNING_CERT, policy);
		XmlRFC execute = rfc.execute();
		return execute != null && execute.getConclusion() != null && Indication.PASSED.equals(execute.getConclusion().getIndication());
	}

	private ChainItem<XmlVTS> satisfyingRevocationDataExists(RevocationWrapper revocationData) {
		return new SatisfyingRevocationDataExistsCheck(result, revocationData, getFailLevelConstraint());
	}

	private ChainItem<XmlVTS> poeExistsAtOrBeforeControlTime(TokenProxy token, TimestampReferenceCategory referenceCategory, Date controlTime) {
		return new POEExistsAtOrBeforeControlTimeCheck(result, token, referenceCategory, controlTime, poe, getFailLevelConstraint());
	}

	private ChainItem<XmlVTS> cryptographicCheck(TokenProxy token, Date validationTime) {
		CryptographicConstraint constraint = policy.getCertificateCryptographicConstraint(context, SubContext.SIGNING_CERT);
		return new CryptographicCheck<XmlVTS>(result, token, validationTime, constraint);
	}

	private boolean isConsistant(CertificateWrapper certificate, RevocationWrapper revocationData) {
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
		if (expiredCertsOnCRL != null && archiveCutOff != null) {
			String revocationSigningCertificateId = revocationData.getSigningCertificateId();
			CertificateWrapper revocCert = diagnosticData.getUsedCertificateById(revocationSigningCertificateId);
			if (revocCert != null) {
				Date expiredCertsRevocationInfo = revocCert.getCertificateTSPServiceExpiredCertsRevocationInfo();
				if (expiredCertsRevocationInfo != null) {
					notAfterRevoc = expiredCertsRevocationInfo;
				}
			}
		}

		return thisUpdate != null && certNotBefore.before(thisUpdate) && (certNotAfter.compareTo(notAfterRevoc) >= 0);
	}

	private boolean isIssuanceBeforeControlTime(RevocationWrapper revocationData) {
		Date issuanceDate = revocationData.getProductionDate();
		return issuanceDate.before(controlTime);
	}

}
