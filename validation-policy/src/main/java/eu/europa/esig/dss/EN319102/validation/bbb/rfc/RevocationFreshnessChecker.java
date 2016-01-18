package eu.europa.esig.dss.EN319102.validation.bbb.rfc;

import java.util.Date;

import eu.europa.esig.dss.EN319102.validation.Chain;
import eu.europa.esig.dss.EN319102.validation.ChainItem;
import eu.europa.esig.dss.EN319102.validation.bbb.rfc.checks.NextUpdateCheck;
import eu.europa.esig.dss.EN319102.validation.bbb.rfc.checks.RevocationDataFreshCheck;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.wrappers.RevocationWrapper;
import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;

/**
 * 5.2.5 Revocation freshness checker
 * This building block checks that a given revocation status information is "fresh" at a given validation time. The
 * freshness
 * of the revocation status information is the maximum accepted difference between the issuance time of the revocation
 * status information and the current time. This process is used by other validation blocks when checking the revocation
 * status of a certificate.
 */
public class RevocationFreshnessChecker extends Chain<XmlRFC> {

	private final RevocationWrapper revocationData;
	private final Date validationDate;
	private final ValidationPolicy policy;

	public RevocationFreshnessChecker(RevocationWrapper revocationData, Date validationDate, ValidationPolicy policy) {
		super(new XmlRFC());

		this.revocationData = revocationData;
		this.validationDate = validationDate;
		this.policy = policy;
	}

	@Override
	protected void initChain() {

		/*
		 * 1) The building block shall get the maximum accepted revocation freshness from the X.509 validation
		 * constraints for the given certificate. If the constraints do not contain a value for the maximum accepted
		 * revocation freshness and the revocation information status is a CRL or an OCSP response IETF RFC 5280 [1],
		 * IETF RFC 6960 [i.12] with a value in the nextUpdate field the time interval between the fields thisUpdate and
		 * nextUpdate shall be used as the value of maximum freshness. If nextUpdate is not set, the building block
		 * shall return with the indication FAILED.
		 * 
		 * NOTE: This means that if the given validation time is after the nextUpdate time, the revocation status
		 * information will not be considered fresh.
		 */
		ChainItem<XmlRFC> item = firstItem = nextUpdateCheck();

		/*
		 * 2) If the issuance time of the revocation information status is after the validation time minus the
		 * considered maximum freshness, the building block shall return the indication PASSED. Otherwise the building
		 * block shall return the indication FAILED.
		 */
		item.setNextItem(revocationDataFreshCheck());
	}

	private ChainItem<XmlRFC> nextUpdateCheck() {
		return new NextUpdateCheck(result, revocationData, validationDate, policy.getRevocationFreshnessConstraint());
	}

	private ChainItem<XmlRFC> revocationDataFreshCheck() {
		return new RevocationDataFreshCheck(result, revocationData, validationDate, policy.getRevocationFreshnessConstraint());
	}

}
