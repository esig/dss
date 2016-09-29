package eu.europa.esig.dss.validation.process.bbb.xcv.rfc;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.NextUpdateCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataAvailableCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataFreshCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataFreshCheckWithNullConstraint;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.TimeConstraint;

/**
 * 5.2.5 Revocation freshness checker This building block checks that a given
 * revocation status information is "fresh" at a given validation time. The
 * freshness of the revocation status information is the maximum accepted
 * difference between the issuance time of the revocation status information and
 * the current time. This process is used by other validation blocks when
 * checking the revocation status of a certificate.
 */
public class RevocationFreshnessChecker extends Chain<XmlRFC> {

	private final RevocationWrapper revocationData;
	private final Date validationDate;
	private final ValidationPolicy policy;

	private final Context context;
	private final SubContext subContext;

	public RevocationFreshnessChecker(RevocationWrapper revocationData, Date validationDate, Context context,
			SubContext subContext, ValidationPolicy policy) {
		super(new XmlRFC());

		this.revocationData = revocationData;
		this.validationDate = validationDate;
		this.policy = policy;

		this.context = context;
		this.subContext = subContext;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlRFC> item = firstItem = revocationDataAvailable(revocationData);

		if (revocationData != null) {
			/*
			 * 1) The building block shall get the maximum accepted revocation
			 * freshness from the X.509 validation constraints for the given
			 * certificate. If the constraints do not contain a value for the
			 * maximum accepted revocation freshness and the revocation
			 * information status is a CRL or an OCSP response IETF RFC 5280
			 * [1], IETF RFC 6960 [i.12] with a value in the nextUpdate field
			 * the time interval between the fields thisUpdate and nextUpdate
			 * shall be used as the value of maximum freshness. If nextUpdate is
			 * not set, the building block shall return with the indication
			 * FAILED.
			 * 
			 * NOTE: This means that if the given validation time is after the
			 * nextUpdate time, the revocation status information will not be
			 * considered fresh.
			 */
			item = item.setNextItem(nextUpdateCheck(revocationData));

			/*
			 * 2) If the issuance time of the revocation information status is
			 * after the validation time minus the considered maximum freshness,
			 * the building block shall return the indication PASSED. Otherwise
			 * the building block shall return the indication FAILED.
			 */
			item = item.setNextItem(revocationDataFreshCheck(revocationData));

			item = item.setNextItem(revocationCryptographic(revocationData));
		}
	}

	private ChainItem<XmlRFC> revocationDataAvailable(RevocationWrapper revocationData) {
		LevelConstraint constraint = policy.getRevocationDataAvailableConstraint(context, subContext);
		return new RevocationDataAvailableCheck(result, revocationData, constraint);
	}

	private ChainItem<XmlRFC> nextUpdateCheck(RevocationWrapper revocationData) {
		LevelConstraint constraint = policy.getRevocationDataNextUpdatePresentConstraint(context, subContext);
		return new NextUpdateCheck(result, revocationData, constraint);
	}

	private ChainItem<XmlRFC> revocationDataFreshCheck(RevocationWrapper revocationData) {
		TimeConstraint timeConstraint = policy.getRevocationFreshnessConstraint();
		/*
		 * The building block shall get the maximum accepted revocation
		 * freshness from the X.509 validation constraints for the given
		 * certificate.
		 */
		if (timeConstraint != null) {
			return new RevocationDataFreshCheck(result, revocationData, validationDate, timeConstraint);
		}
		/*
		 * If the constraints do not contain a value for the maximum accepted
		 * revocation freshness and the revocation information status is a CRL
		 * or an OCSP response IETF RFC 5280 [1], IETF RFC 6960 [i.12] with a
		 * value in the nextUpdate field the time interval between the fields
		 * thisUpdate and nextUpdate shall be used as the value of maximum
		 * freshness.
		 */
		else {
			return new RevocationDataFreshCheckWithNullConstraint(result, revocationData, validationDate,
					getFailLevelConstraint());
		}

	}

	private ChainItem<XmlRFC> revocationCryptographic(RevocationWrapper revocationData) {
		CryptographicConstraint cryptographicConstraint = policy.getCertificateCryptographicConstraint(context,
				subContext);
		return new CryptographicCheck<XmlRFC>(result, revocationData, validationDate, cryptographicConstraint);
	}

}
