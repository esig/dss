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

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ArchiveTimeStampCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CertifiedRolesCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ClaimedRolesCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CommitmentTypeIndicationsCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentHintsCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentIdentifierCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentTimeStampCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentTypeCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CounterSignatureCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.DocumentTimeStampCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.KeyIdentifierMatchCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.KeyIdentifierPresentCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.MessageDigestOrSignedPropertiesCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SignatureTimeStampCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SignerLocationCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SigningTimeCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.StructuralValidationCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ValidationDataRefsOnlyTimeStampCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ValidationDataTimeStampCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampMessageImprintCheck;

import java.util.Date;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public class SignatureAcceptanceValidation extends AbstractAcceptanceValidation<SignatureWrapper> {

	/** The Diagnostic Data */
	private final DiagnosticData diagnosticData;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param currentTime {@link Date} validation time
	 * @param signature {@link SignatureWrapper}
	 * @param context {@link Context}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public SignatureAcceptanceValidation(I18nProvider i18nProvider, DiagnosticData diagnosticData, Date currentTime,
										 SignatureWrapper signature, Context context, ValidationPolicy validationPolicy) {
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

		item = item.setNextItem(signingCertificateAttributePresent());

		if (token.isSigningCertificateReferencePresent()) {
			/*
			 * 5.2.8.4.2.1 Processing signing certificate reference constraint
			 *
			 * If the Signing Certificate Identifier attribute contains references to
			 * other certificates in the path, the building block shall check each of
			 * the certificates in the certification path against these references.
			 *
			 * When this property contains one or more references to certificates other than
			 * those present in the certification path, the building block shall return
			 * the indication INDETERMINATE with the sub-indication SIG_CONSTRAINTS_FAILURE.
			 */
			item = item.setNextItem(unicitySigningCertificateAttribute());

			item = item.setNextItem(signingCertificateReferencesValidity());

			/*
			 * When one or more certificates in the certification path are not referenced
			 * by this property, and the signature policy mandates references to all
			 * the certificates in the certification path to be present, the building block shall
			 * return the indication INDETERMINATE with the sub-indication SIG_CONSTRAINTS_FAILURE.
			 */
			item = item.setNextItem(allCertificatesInPathReferenced());
		}

		// 'kid' (key identifier) verification for JAdES
		if (SignatureForm.JAdES.equals(token.getSignatureFormat().getSignatureForm())) {

			item = item.setNextItem(keyIdentifierPresent());

			if (token.getKeyIdentifierReference() != null) {
				item = item.setNextItem(keyIdentifierMatch());
			}

		}

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

		// claimed-roles
		item = item.setNextItem(claimedRoles());

		// certified-roles
		item = item.setNextItem(certifiedRoles());

		// TODO signer-attributes

		// content-timestamp
		item = item.setNextItem(contentTimeStamp());

		// content-timestamp message-imprint
		for (TimestampWrapper contentTimestamp : token.getContentTimestamps()) {
			item = item.setNextItem(contentTimestampMessageImprint(contentTimestamp));
		}

		// counter-signature
		item = item.setNextItem(counterSignature());

		// signature-time-stamp
		item = item.setNextItem(signatureTimeStamp());

		// validation-data-time-stamp
		item = item.setNextItem(validationDataTimeStamp());

		// validation-data-refs-only-time-stamp
		item = item.setNextItem(validationDataRefsOnlyTimeStamp());

		// archive-time-stamp
		item = item.setNextItem(archiveTimeStamp());

		// document-time-stamp (PAdES only)
		if (SignatureForm.PAdES.equals(token.getSignatureFormat().getSignatureForm())) {
			item = item.setNextItem(documentTimeStamp());
		}

		// cryptographic check
		item = cryptographic(item);

		// cryptographic check on signed attributes
		item = cryptographicSignedAttributes(item);
	}

	private ChainItem<XmlSAV> structuralValidation() {
		LevelConstraint constraint = validationPolicy.getStructuralValidationConstraint(context);
		return new StructuralValidationCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> keyIdentifierPresent() {
		LevelConstraint constraint = validationPolicy.getKeyIdentifierPresent(context);
		return new KeyIdentifierPresentCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> keyIdentifierMatch() {
		LevelConstraint constraint = validationPolicy.getKeyIdentifierMatch(context);
		return new KeyIdentifierMatchCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> signingTime() {
		LevelConstraint constraint = validationPolicy.getSigningTimeConstraint(context);
		return new SigningTimeCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentType() {
		ValueConstraint constraint = validationPolicy.getContentTypeConstraint(context);
		return new ContentTypeCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentHints() {
		ValueConstraint constraint = validationPolicy.getContentHintsConstraint(context);
		return new ContentHintsCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentIdentifier() {
		ValueConstraint constraint = validationPolicy.getContentIdentifierConstraint(context);
		return new ContentIdentifierCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> messageDigestOrSignedProperties() {
		LevelConstraint constraint = validationPolicy.getMessageDigestOrSignedPropertiesConstraint(context);
		return new MessageDigestOrSignedPropertiesCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> commitmentTypeIndications() {
		MultiValuesConstraint constraint = validationPolicy.getCommitmentTypeIndicationConstraint(context);
		return new CommitmentTypeIndicationsCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> signerLocation() {
		LevelConstraint constraint = validationPolicy.getSignerLocationConstraint(context);
		return new SignerLocationCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentTimeStamp() {
		LevelConstraint constraint = validationPolicy.getContentTimeStampConstraint(context);
		return new ContentTimeStampCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentTimestampMessageImprint(TimestampWrapper contentTimestamp) {
		LevelConstraint constraint = validationPolicy.getContentTimeStampMessageImprintConstraint(context);
		return new TimestampMessageImprintCheck<>(i18nProvider, result, contentTimestamp, constraint);
	}

	private ChainItem<XmlSAV> claimedRoles() {
		MultiValuesConstraint constraint = validationPolicy.getClaimedRoleConstraint(context);
		return new ClaimedRolesCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> certifiedRoles() {
		MultiValuesConstraint constraint = validationPolicy.getCertifiedRolesConstraint(context);
		return new CertifiedRolesCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> counterSignature() {
		LevelConstraint constraint = validationPolicy.getCounterSignatureConstraint(context);
		return new CounterSignatureCheck(i18nProvider, result, diagnosticData, token, constraint);
	}

	private ChainItem<XmlSAV> signatureTimeStamp() {
		LevelConstraint constraint = validationPolicy.getSignatureTimeStampConstraint(context);
		return new SignatureTimeStampCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> validationDataTimeStamp() {
		LevelConstraint constraint = validationPolicy.getValidationDataTimeStampConstraint(context);
		return new ValidationDataTimeStampCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> validationDataRefsOnlyTimeStamp() {
		LevelConstraint constraint = validationPolicy.getValidationDataRefsOnlyTimeStampConstraint(context);
		return new ValidationDataRefsOnlyTimeStampCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> archiveTimeStamp() {
		LevelConstraint constraint = validationPolicy.getArchiveTimeStampConstraint(context);
		return new ArchiveTimeStampCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> documentTimeStamp() {
		LevelConstraint constraint = validationPolicy.getDocumentTimeStampConstraint(context);
		return new DocumentTimeStampCheck(i18nProvider, result, token, constraint);
	}

}
