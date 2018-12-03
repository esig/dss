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
package eu.europa.esig.dss.validation.process.bbb.sav;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CertifiedRolesCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ClaimedRolesCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CommitmentTypeIndicationsCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentHintsCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentIdentifierCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentTimestampCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentTypeCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CounterSignatureCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SignerLocationCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SigningTimeCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.StructuralValidationCheck;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;
import eu.europa.esig.jaxb.policy.ValueConstraint;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public class SignatureAcceptanceValidation extends AbstractAcceptanceValidation<SignatureWrapper> {

	private final Context context;

	public SignatureAcceptanceValidation(DiagnosticData diagnosticData, Date currentTime, SignatureWrapper signature, Context context,
			ValidationPolicy validationPolicy) {
		super(diagnosticData, signature, currentTime, validationPolicy);
		this.context = context;
	}

	@Override
	protected void initChain() {
		ChainItem<XmlSAV> item = firstItem = structuralValidation();

		// signing-time
		item = item.setNextItem(signingTime());

		// content-type
		item = item.setNextItem(contentType());

		// content-hints
		item = item.setNextItem(contentHints());

		// TODO content-reference

		// content-identifier
		item = item.setNextItem(contentIdentifier());

		// commitment-type-indication
		item = item.setNextItem(commitmentTypeIndications());

		// signer-location
		item = item.setNextItem(signerLocation());

		// TODO signer-attributes

		// content-timestamp
		item = item.setNextItem(contentTimestamp());

		// countersignature
		item = item.setNextItem(countersignature());

		// claimed-roles
		item = item.setNextItem(claimedRoles());

		// certified-roles
		item = item.setNextItem(certifiedRoles());

		// cryptographic check
		item = item.setNextItem(signatureCryptographic());
	}

	private ChainItem<XmlSAV> structuralValidation() {
		LevelConstraint constraint = validationPolicy.getStructuralValidationConstraint(context);
		return new StructuralValidationCheck(result, token, constraint);
	}

	private ChainItem<XmlSAV> signingTime() {
		LevelConstraint constraint = validationPolicy.getSigningTimeConstraint();
		return new SigningTimeCheck(result, token, constraint);
	}

	private ChainItem<XmlSAV> contentType() {
		ValueConstraint constraint = validationPolicy.getContentTypeConstraint();
		return new ContentTypeCheck(result, token, constraint);
	}

	private ChainItem<XmlSAV> contentHints() {
		ValueConstraint constraint = validationPolicy.getContentHintsConstraint();
		return new ContentHintsCheck(result, token, constraint);
	}

	private ChainItem<XmlSAV> contentIdentifier() {
		ValueConstraint constraint = validationPolicy.getContentIdentifierConstraint();
		return new ContentIdentifierCheck(result, token, constraint);
	}

	private ChainItem<XmlSAV> commitmentTypeIndications() {
		MultiValuesConstraint constraint = validationPolicy.getCommitmentTypeIndicationConstraint();
		return new CommitmentTypeIndicationsCheck(result, token, constraint);
	}

	private ChainItem<XmlSAV> signerLocation() {
		LevelConstraint constraint = validationPolicy.getSignerLocationConstraint();
		return new SignerLocationCheck(result, token, constraint);
	}

	private ChainItem<XmlSAV> contentTimestamp() {
		LevelConstraint constraint = validationPolicy.getContentTimestampConstraint();
		return new ContentTimestampCheck(result, diagnosticData, token, constraint);
	}

	private ChainItem<XmlSAV> countersignature() {
		LevelConstraint constraint = validationPolicy.getCounterSignatureConstraint();
		return new CounterSignatureCheck(result, diagnosticData, token, constraint);
	}

	private ChainItem<XmlSAV> claimedRoles() {
		MultiValuesConstraint constraint = validationPolicy.getClaimedRoleConstraint();
		return new ClaimedRolesCheck(result, token, constraint);
	}

	private ChainItem<XmlSAV> certifiedRoles() {
		MultiValuesConstraint constraint = validationPolicy.getCertifiedRolesConstraint();
		return new CertifiedRolesCheck(result, token, constraint);
	}

	private ChainItem<XmlSAV> signatureCryptographic() {
		CryptographicConstraint constraint = validationPolicy.getSignatureCryptographicConstraint(context);
		return new CryptographicCheck<XmlSAV>(result, token, currentTime, constraint);
	}

}
