package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.rfc.RevocationFreshnessChecker;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.POEExistsAtOrBeforeControlTimeCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.RevocationDataExistsCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;

public class ValidationTimeSliding extends Chain<XmlVTS> {

	private final DiagnosticData diagnosticData;
	private final TokenProxy token;
	private final Date currentTime;

	private final POEExtraction poe;
	private final ValidationPolicy policy;

	private Date controlTime;

	public ValidationTimeSliding(DiagnosticData diagnosticData, TokenProxy token, Date currentTime, POEExtraction poe, ValidationPolicy policy) {
		super(new XmlVTS());

		this.diagnosticData = diagnosticData;
		this.token = token;
		this.currentTime = currentTime;

		this.poe = poe;
		this.policy = policy;
	}

	@Override
	protected void initChain() {

		/*
		 * 5.6.2.2.4 Processing
		 * 
		 * 1) The building block shall initialize control-time to the current date/time.
		 * 
		 * NOTE 1: Control-time is an internal variable that is used within the algorithms and not part of the core
		 * results of the validation process.
		 */
		controlTime = currentTime;

		List<String> certificateChainIds = token.getCertificateChainIds();
		if (CollectionUtils.isNotEmpty(certificateChainIds)) {

			/*
			 * 2) For each certificate in the chain starting from the first certificate (the certificate issued by the
			 * trust anchor):
			 */
			Collections.reverse(certificateChainIds); // trusted_list -> ... -> signature

			for (String certificateId : certificateChainIds) {
				CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certificateId);
				if (certificate.isTrusted()) {
					continue;
				}

				/*
				 * a) The building block shall find revocation status information satisfying the following:
				 * 
				 * - The revocation status information is consistent with the rules conditioning its use to check the
				 * revocation status of the considered certificate. In the case of a CRL, it shall satisfy the checks
				 * specified in IETF RFC 5280 [1] clause 6.3; and
				 * 
				 * - The issuance date of the revocation status information is before control-time.
				 * If more than one revocation status is found, the building block shall consider the most recent one
				 * and shall go to the next step.
				 * 
				 * If there is no such information, The building block shall return the indication INDETERMINATE with
				 * the sub-indication NO_POE.
				 */
				ChainItem<XmlVTS> item = revocationDataExists(certificate);
				if (firstItem == null) {
					firstItem = item;
				}

				RevocationWrapper revocationData = certificate.getRevocationData();
				if (revocationData != null) {
					Date revocationProductionDate = revocationData.getProductionDate();
					if (revocationProductionDate != null && revocationProductionDate.before(controlTime)) {

						/*
						 * b) If the set of POEs contains a proof of existence of the certificate and the revocation
						 * status information at (or before) control-time, the building block shall go to step c).
						 * 
						 * Otherwise, the building block shall return the indication INDETERMINATE with the
						 * sub-indication NO_POE.
						 */
						item = item.setNextItem(poeExistsAtOrBeforeControlTime(certificate.getId(), controlTime));

						// TODO missing info in DiagnosticData
						// item.setNextItem(poeExistsAtOrBeforeControlTime(revocationData.getId(), controlTime));

						/*
						 * c) The update of the value of control-time is as follows:
						 * 
						 * - If the certificate is marked as revoked in the revocation status information, the building
						 * block shall set control-time to the revocation time.
						 * 
						 * - If the certificate is not marked as revoked, the building block shall run the Revocation
						 * Freshness Checker with the used revocation information status, the certificate for which the
						 * revocation status is being checked and the control-time. If it returns FAILED, the building
						 * block shall set control-time to the issuance time of the revocation status information.
						 * 
						 * Otherwise, the building block shall not change the value of control-time.
						 */
						// TODO correct ??
						if (certificate.isRevoked()) {
							controlTime = revocationData.getRevocationDate();
						} else if (!isFresh(revocationData, controlTime)) {
							controlTime = revocationData.getProductionDate();
						}

						/*
						 * d) The building block shall apply the cryptographic constraints to the certificate and the
						 * revocation status information against the control-time. If the certificate (or the revocation
						 * status information) does not match these constraints, the building block shall set
						 * control-time to the lowest time up to which the listed algorithms were considered reliable.
						 */
						// TODO crypto check

					}
				}
			}
		}
	}

	@Override
	protected void addAdditionalInfo() {
		result.setControlTime(controlTime);
	}

	private boolean isFresh(RevocationWrapper revocationData, Date controlTime) {
		RevocationFreshnessChecker rfc = new RevocationFreshnessChecker(revocationData, controlTime, policy);
		XmlRFC execute = rfc.execute();
		return execute != null && execute.getConclusion() != null && Indication.VALID.equals(execute.getConclusion().getIndication());
	}

	private ChainItem<XmlVTS> revocationDataExists(CertificateWrapper certificate) {
		return new RevocationDataExistsCheck(result, certificate, getFailLevelConstraint());
	}

	private ChainItem<XmlVTS> poeExistsAtOrBeforeControlTime(String id, Date controlTime) {
		return new POEExistsAtOrBeforeControlTimeCheck(result, id, controlTime, poe, getFailLevelConstraint());
	}

}
