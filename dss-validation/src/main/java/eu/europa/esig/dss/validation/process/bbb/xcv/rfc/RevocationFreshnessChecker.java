/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.bbb.xcv.rfc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.DurationRule;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.NextUpdateCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataFreshCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataFreshCheckWithNullConstraint;

import java.util.Date;

/**
 * 5.2.5 Revocation freshness checker This building block checks that a given
 * revocation status information is "fresh" at a given validation time. The
 * freshness of the revocation status information is the maximum accepted
 * difference between the issuance time of the revocation status information and
 * the current time. This process is used by other validation blocks when
 * checking the revocation status of a certificate.
 */
public class RevocationFreshnessChecker extends Chain<XmlRFC> {

	/** Revocation data to check */
	private final RevocationWrapper revocationData;

	/** Validation time */
	private final Date validationDate;

	/** Validation policy */
	private final ValidationPolicy policy;

	/** Validation context */
	private final Context context;

	/** Validation subContext */
	private final SubContext subContext;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param revocationData {@link RevocationWrapper}
	 * @param validationDate {@link Date}
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @param policy {@link ValidationPolicy}
	 */
	public RevocationFreshnessChecker(I18nProvider i18nProvider, RevocationWrapper revocationData, Date validationDate,
									  Context context, SubContext subContext, ValidationPolicy policy) {
		super(i18nProvider, new XmlRFC());

		this.revocationData = revocationData;
		this.validationDate = validationDate;
		this.policy = policy;

		this.context = context;
		this.subContext = subContext;

		if (revocationData != null) {
			result.setId(revocationData.getId());
		}
	}
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.REVOCATION_FRESHNESS_CHECKER;
	}

	@Override
	protected void initChain() {
		ChainItem<XmlRFC> item = null;

		if (revocationData != null) {

			result.setId(revocationData.getId());

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
			DurationRule revocationFreshnessConstraint = policy.getRevocationFreshnessConstraint(context, subContext);
			if (revocationFreshnessConstraint == null || Level.IGNORE.equals(revocationFreshnessConstraint.getLevel())) {
				switch (revocationData.getRevocationType()) {
					case CRL:
						item = firstItem = crlNextUpdateCheck(revocationData);
						break;
					case OCSP:
						item = firstItem = ocspNextUpdateCheck(revocationData);
						break;
					default:
						throw new IllegalArgumentException(String.format("The RevocationType '%s' is not supported!",
								revocationData.getRevocationType()));
				}
			}
			/*
			 * 2) If the issuance time of the revocation information status is
			 * after the validation time minus the considered maximum freshness,
			 * the building block shall return the indication PASSED. Otherwise
			 * the building block shall return the indication FAILED.
			 */
			if (item == null) {
				item = firstItem = revocationDataFreshCheck(revocationData, revocationFreshnessConstraint);
			} else {
				item = item.setNextItem(revocationDataFreshCheck(revocationData, revocationFreshnessConstraint));
			}

		}
	}

	private ChainItem<XmlRFC> crlNextUpdateCheck(RevocationWrapper revocationData) {
		LevelRule constraint = policy.getCRLNextUpdatePresentConstraint(context, subContext);
		return new NextUpdateCheck(i18nProvider, result, revocationData, constraint);
	}

	private ChainItem<XmlRFC> ocspNextUpdateCheck(RevocationWrapper revocationData) {
		LevelRule constraint = policy.getOCSPNextUpdatePresentConstraint(context, subContext);
		return new NextUpdateCheck(i18nProvider, result, revocationData, constraint);
	}

	private ChainItem<XmlRFC> revocationDataFreshCheck(RevocationWrapper revocationData, DurationRule revocationFreshnessConstraint) {
		/*
		 * The building block shall get the maximum accepted revocation
		 * freshness from the X.509 validation constraints for the given
		 * certificate.
		 */
		if (revocationFreshnessConstraint != null) {
			return new RevocationDataFreshCheck(i18nProvider, result, revocationData, validationDate, revocationFreshnessConstraint);
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
			LevelRule constraint = policy.getRevocationFreshnessNextUpdateConstraint(context, subContext);
			return new RevocationDataFreshCheckWithNullConstraint(i18nProvider, result, revocationData, validationDate, constraint);
		}
	}

}
