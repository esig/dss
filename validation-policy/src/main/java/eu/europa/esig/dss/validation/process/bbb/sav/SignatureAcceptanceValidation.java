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

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CertifiedRolesCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ClaimedRolesCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CommitmentTypeIndicationsCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentHintsCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentIdentifierCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentTimestampCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentTypeCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CounterSignatureCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.MessageDigestOrSignedPropertiesCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SignerLocationCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SigningTimeCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.StructuralValidationCheck;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public class SignatureAcceptanceValidation extends AbstractAcceptanceValidation<SignatureWrapper> {

	private final DiagnosticData diagnosticData;

	public SignatureAcceptanceValidation(I18nProvider i18nProvider, DiagnosticData diagnosticData, Date currentTime, SignatureWrapper signature, 
			Context context, ValidationPolicy validationPolicy) {
		super(i18nProvider, signature, currentTime, context, validationPolicy);
		this.diagnosticData = diagnosticData;
	}
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.SIGNATURE_ACCEPTANCE_VALIDATION;
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
		
		// message-digest for CAdES/PAdES and SignedProperties for XAdES are present
		if (!SignatureForm.JAdES.equals(token.getSignatureFormat().getSignatureForm())) {
			item = item.setNextItem(messageDigestOrSignedProperties());
		}

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
		item = item.setNextItem(cryptographic());
	}

	private ChainItem<XmlSAV> structuralValidation() {
		LevelConstraint constraint = validationPolicy.getStructuralValidationConstraint(context);
		return new StructuralValidationCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> signingTime() {
		LevelConstraint constraint = validationPolicy.getSigningTimeConstraint();
		return new SigningTimeCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentType() {
		ValueConstraint constraint = validationPolicy.getContentTypeConstraint();
		return new ContentTypeCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentHints() {
		ValueConstraint constraint = validationPolicy.getContentHintsConstraint();
		return new ContentHintsCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentIdentifier() {
		ValueConstraint constraint = validationPolicy.getContentIdentifierConstraint();
		return new ContentIdentifierCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> messageDigestOrSignedProperties() {
		LevelConstraint constraint = validationPolicy.getMessageDigestOrSignedPropertiesConstraint();
		return new MessageDigestOrSignedPropertiesCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> commitmentTypeIndications() {
		MultiValuesConstraint constraint = validationPolicy.getCommitmentTypeIndicationConstraint();
		return new CommitmentTypeIndicationsCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> signerLocation() {
		LevelConstraint constraint = validationPolicy.getSignerLocationConstraint();
		return new SignerLocationCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentTimestamp() {
		LevelConstraint constraint = validationPolicy.getContentTimestampConstraint();
		return new ContentTimestampCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> countersignature() {
		LevelConstraint constraint = validationPolicy.getCounterSignatureConstraint();
		return new CounterSignatureCheck(i18nProvider, result, diagnosticData, token, constraint);
	}

	private ChainItem<XmlSAV> claimedRoles() {
		MultiValuesConstraint constraint = validationPolicy.getClaimedRoleConstraint();
		return new ClaimedRolesCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> certifiedRoles() {
		MultiValuesConstraint constraint = validationPolicy.getCertifiedRolesConstraint();
		return new CertifiedRolesCheck(i18nProvider, result, token, constraint);
	}

}
