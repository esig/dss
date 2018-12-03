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

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.AllFilesSignedCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataExistenceCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataIntactCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.SignatureIntactCheck;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.2.7 Cryptographic verification
 * This building block checks the integrity of the signed data by performing the cryptographic verifications.
 */
public class CryptographicVerification extends Chain<XmlCV> {

	private final DiagnosticData diagnosticData;
	private final TokenProxy token;

	private final ValidationPolicy validationPolicy;
	private final Context context;

	public CryptographicVerification(DiagnosticData diagnosticData, TokenProxy token, Context context, ValidationPolicy validationPolicy) {
		super(new XmlCV());

		this.diagnosticData = diagnosticData;
		this.token = token;
		this.context = context;
		this.validationPolicy = validationPolicy;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlCV> item = null;

		/*
		 * 5.2.7.4 Processing
		 * The first and second steps as well as the Data To Be Signed depend on the signature type. The technical
		 * details on how to do this correctly are out of scope for the present document. See ETSI EN 319 122-1 [i.2],
		 * ETSI EN 319
		 * 122-2 [i.3], ETSI EN 319 132-1 [i.4], ETSI EN 319 132-2 [i.5], ETSI EN 319 142-1 [i.6], ETSI EN 319 142-2
		 * [i.7] and IETF
		 * RFC 3852 [i.8] for details.
		 */

		List<XmlDigestMatcher> digestMatchers = token.getDigestMatchers();
		if (Utils.isCollectionNotEmpty(digestMatchers)) {
			for (XmlDigestMatcher digestMatcher : digestMatchers) {

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

		/* ASiC Container */
		if (diagnosticData.isContainerInfoPresent() && Context.SIGNATURE == context) {
			item = item.setNextItem(allFilesSignedCheck());
		}
	}

	private ChainItem<XmlCV> referenceDataFound(XmlDigestMatcher digestMatcher) {
		LevelConstraint constraint = validationPolicy.getReferenceDataExistenceConstraint(context);
		return new ReferenceDataExistenceCheck(result, digestMatcher, constraint);
	}

	private ChainItem<XmlCV> referenceDataIntact(XmlDigestMatcher digestMatcher) {
		LevelConstraint constraint = validationPolicy.getReferenceDataIntactConstraint(context);
		return new ReferenceDataIntactCheck(result, digestMatcher, constraint);
	}

	private ChainItem<XmlCV> signatureIntact() {
		LevelConstraint constraint = validationPolicy.getSignatureIntactConstraint(context);
		return new SignatureIntactCheck(result, token, constraint);
	}


	private ChainItem<XmlCV> allFilesSignedCheck() {
		LevelConstraint constraint = validationPolicy.getAllFilesSignedConstraint();
		return new AllFilesSignedCheck(result, (SignatureWrapper) token, diagnosticData.getContainerInfo(), constraint);
	}

}
