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
import eu.europa.esig.dss.validation.wrappers.CertificateWrapper;
import eu.europa.esig.dss.validation.wrappers.DiagnosticData;
import eu.europa.esig.dss.validation.wrappers.RevocationWrapper;
import eu.europa.esig.dss.validation.wrappers.TokenProxy;

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
		 * 1) The building block shall initialize control-time to the current date/time.
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

				ChainItem<XmlVTS> item = revocationDataExists(certificate);
				if (firstItem == null) {
					firstItem = item;
				}

				RevocationWrapper revocationData = certificate.getRevocationData();
				if (revocationData != null) {
					Date revocationProductionDate = revocationData.getProductionDate();
					if (revocationProductionDate != null && revocationProductionDate.before(controlTime)) {

						item.setNextItem(poeExistsAtOrBeforeControlTime(certificate.getId(), controlTime));

						// TODO item.setNextItem(poeExistsAtOrBeforeControlTime(revocationData.getId(), controlTime));

						// TODO correct ??
						if (certificate.isRevoked()) {
							controlTime = revocationData.getRevocationDate();
						} else if (!isFresh(revocationData, controlTime)) {
							controlTime = revocationData.getProductionDate();
						}

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
