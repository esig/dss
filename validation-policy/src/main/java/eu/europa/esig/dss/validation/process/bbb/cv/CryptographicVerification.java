/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.bbb.cv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.EvidenceRecordHashTreeRenewalTimestampCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ManifestEntryExistenceCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataExistenceCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataIntactCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.SignatureIntactCheck;

import java.util.List;

/**
 * 5.2.7 Cryptographic verification
 * This building block checks the integrity of the signed data by performing the cryptographic verifications.
 */
public class CryptographicVerification extends Chain<XmlCV> {

	/** Diagnostic data */
	private final DiagnosticData diagnosticData;

	/** The token to verify */
	private final TokenProxy token;

	/** The validation policy */
	private final ValidationPolicy validationPolicy;

	/** The validation context */
	private final Context context;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param token {@link TokenProxy}
	 * @param context {@link Context}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public CryptographicVerification(I18nProvider i18nProvider, DiagnosticData diagnosticData, TokenProxy token,
									 Context context, ValidationPolicy validationPolicy) {
		super(i18nProvider, new XmlCV());
		this.diagnosticData = diagnosticData;
		this.token = token;
		this.context = context;
		this.validationPolicy = validationPolicy;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.CRYPTOGRAPHIC_VERIFICATION;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlCV> item = null;

		/*
		 * 5.2.7.4 Processing The first and second steps as well as 
		 * the Data To Be Signed depend on the signature type. The technical details 
		 * on how to do this correctly are out of scope for the present document. 
		 * See ETSI EN 319 122-1 [i.2], ETSI EN 319 122-2 [i.3], ETSI EN 319 132-1 [i.4], 
		 * ETSI EN 319 132-2 [i.5], ETSI EN 319 142-1 [i.6], ETSI EN 319 142-2 [i.7] 
		 * and IETF RFC 3852 [i.8] for details.
		 */

		List<XmlDigestMatcher> digestMatchers = token.getDigestMatchers();
		
		if (Utils.isCollectionNotEmpty(digestMatchers)) {
			for (XmlDigestMatcher digestMatcher : digestMatchers) {
				if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == digestMatcher.getType()) {
					// Evidence Records optionally allow additional digests to be present within first data group
					continue;
				}
				/*
				 * 1) The building block shall obtain the signed data object(s) if not provided
				 * in the inputs (e.g. by dereferencing an URI present in the signature). If the
				 * signed data object(s) cannot be obtained, the building block shall return the
				 * indication INDETERMINATE with the sub-indication SIGNED_DATA_NOT_FOUND.
				 */
				ChainItem<XmlCV> referenceDataFound = referenceDataFound(digestMatcher);
				if (item == null) {
					firstItem = item = referenceDataFound;
				} else {
					item = item.setNextItem(referenceDataFound);
				}
				/*
				 * 2) The SVA shall check the integrity of the signed data objects. In case of
				 * failure, the building block shall return the indication FAILED with the
				 * sub-indication HASH_FAILURE.
				 */
				item = item.setNextItem(referenceDataIntact(digestMatcher));
			}

			if (isEvidenceRecordHashTreeRenewalTimestamp()) {

				ChainItem<XmlCV> evidenceRecordHashTreeRenewalTimestamp = evidenceRecordHashTreeRenewalTimestamp();
				if (item == null) {
					firstItem = item = evidenceRecordHashTreeRenewalTimestamp;
				} else {
					item = item.setNextItem(evidenceRecordHashTreeRenewalTimestamp);
				}

			}
		}

		// If we are verifying a signature based on Manifest, check if at least one
		// entry is found
		if (containsManifest(digestMatchers)) {
			ChainItem<XmlCV> manifestEntryExistence = manifestEntryExistence(digestMatchers);
			if (item == null) {
				firstItem = item = manifestEntryExistence;
			} else {
				item = item.setNextItem(manifestEntryExistence);
			}
		}

		/*
		 * 3) The building block shall verify the cryptographic signature using the public key extracted from the
		 * signing certificate in the chain, the signature value and the signature algorithm extracted from the
		 * signature. If this cryptographic verification outputs a success indication, the building block shall return
		 * the indication PASSED.
		 * 
		 * 4) Otherwise, the building block shall return the indication FAILED and the sub-indication
		 * SIG_CRYPTO_FAILURE.
		 */
		ChainItem<XmlCV> signatureIntact = signatureIntact();
		if (item == null) {
			firstItem = item = signatureIntact;
		} else {
			item = item.setNextItem(signatureIntact);
		}
		
	}

	private boolean containsManifest(List<XmlDigestMatcher> digestMatchers) {
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			if (DigestMatcherType.MANIFEST.equals(xmlDigestMatcher.getType())) {
				return true;
			}
		}
		return false;
	}

	private ChainItem<XmlCV> referenceDataFound(XmlDigestMatcher digestMatcher) {
		LevelConstraint constraint = validationPolicy.getReferenceDataExistenceConstraint(context);
		return new ReferenceDataExistenceCheck<>(i18nProvider, result, digestMatcher, constraint);
	}

	private ChainItem<XmlCV> referenceDataIntact(XmlDigestMatcher digestMatcher) {
		LevelConstraint constraint = validationPolicy.getReferenceDataIntactConstraint(context);
		return new ReferenceDataIntactCheck<>(i18nProvider, result, digestMatcher, constraint);
	}

	private ChainItem<XmlCV> manifestEntryExistence(List<XmlDigestMatcher> digestMatchers) {
		LevelConstraint constraint = validationPolicy.getManifestEntryObjectExistenceConstraint(context);
		return new ManifestEntryExistenceCheck(i18nProvider, result, digestMatchers, constraint);
	}

	private ChainItem<XmlCV> signatureIntact() {
		LevelConstraint constraint = validationPolicy.getSignatureIntactConstraint(context);
		return new SignatureIntactCheck<>(i18nProvider, result, token, context, constraint);
	}

	private boolean isEvidenceRecordHashTreeRenewalTimestamp() {
		if (token instanceof TimestampWrapper) {
			TimestampWrapper timestampWrapper = (TimestampWrapper) token;
			return timestampWrapper.getType().isEvidenceRecordTimestamp() &&
					EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP == timestampWrapper.getEvidenceRecordTimestampType();
		}
		return false;
	}

	private ChainItem<XmlCV> evidenceRecordHashTreeRenewalTimestamp() {
		LevelConstraint constraint = validationPolicy.getEvidenceRecordHashTreeRenewalConstraint();
		return new EvidenceRecordHashTreeRenewalTimestampCheck(i18nProvider, result, diagnosticData, (TimestampWrapper) token, constraint);
	}

}
