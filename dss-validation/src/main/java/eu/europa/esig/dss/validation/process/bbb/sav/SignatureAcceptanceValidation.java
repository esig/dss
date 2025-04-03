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
package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.policy.ValueRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ArchiveTimeStampCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CertifiedRolesCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ClaimedRolesCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CommitmentTypeIndicationsCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentHintsCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentIdentifierCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentTimeStampCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.ContentTimestampBasicValidationCheck;
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
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampMessageImprintWithIdCheck;

import java.util.Date;
import java.util.Map;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public class SignatureAcceptanceValidation extends AbstractAcceptanceValidation<SignatureWrapper> {

	/** The Diagnostic Data */
	private final DiagnosticData diagnosticData;

	/** A map of BasicBuildingBlocks */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param currentTime {@link Date} validation time
	 * @param signature {@link SignatureWrapper}
	 * @param context {@link Context}
	 * @param bbbs a map of {@link XmlBasicBuildingBlocks}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public SignatureAcceptanceValidation(I18nProvider i18nProvider, DiagnosticData diagnosticData, Date currentTime,
										 SignatureWrapper signature, Context context,
										 Map<String, XmlBasicBuildingBlocks> bbbs, ValidationPolicy validationPolicy) {
		super(i18nProvider, signature, currentTime, context, validationPolicy);
		this.diagnosticData = diagnosticData;
		this.bbbs = bbbs;
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

		// content-timestamp
		for (TimestampWrapper contentTimestamp : token.getContentTimestamps()) {

			XmlBasicBuildingBlocks contentTimestampBBB = bbbs.get(contentTimestamp.getId());
			if (contentTimestampBBB != null) {
				// NOTE: if TIMESTAMP validation level has been reached
				item = item.setNextItem(contentTimestampBasicValidation(contentTimestamp, contentTimestampBBB.getConclusion()));
			}

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
		LevelRule constraint = validationPolicy.getStructuralValidationConstraint(context);
		return new StructuralValidationCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> keyIdentifierPresent() {
		LevelRule constraint = validationPolicy.getKeyIdentifierPresent(context);
		return new KeyIdentifierPresentCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> keyIdentifierMatch() {
		LevelRule constraint = validationPolicy.getKeyIdentifierMatch(context);
		return new KeyIdentifierMatchCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> signingTime() {
		LevelRule constraint = validationPolicy.getSigningDurationRule(context);
		return new SigningTimeCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentType() {
		ValueRule constraint = validationPolicy.getContentTypeConstraint(context);
		return new ContentTypeCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentHints() {
		ValueRule constraint = validationPolicy.getContentHintsConstraint(context);
		return new ContentHintsCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentIdentifier() {
		ValueRule constraint = validationPolicy.getContentIdentifierConstraint(context);
		return new ContentIdentifierCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> messageDigestOrSignedProperties() {
		LevelRule constraint = validationPolicy.getMessageDigestOrSignedPropertiesConstraint(context);
		return new MessageDigestOrSignedPropertiesCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> commitmentTypeIndications() {
		MultiValuesRule constraint = validationPolicy.getCommitmentTypeIndicationConstraint(context);
		return new CommitmentTypeIndicationsCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> signerLocation() {
		LevelRule constraint = validationPolicy.getSignerLocationConstraint(context);
		return new SignerLocationCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentTimeStamp() {
		LevelRule constraint = validationPolicy.getContentTimeStampConstraint(context);
		return new ContentTimeStampCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> contentTimestampBasicValidation(final TimestampWrapper timestamp, XmlConclusion xmlConclusion) {
		return new ContentTimestampBasicValidationCheck(i18nProvider, result, timestamp, xmlConclusion,
				getTimestampBasicValidationConstraintLevel());
	}

	private ChainItem<XmlSAV> contentTimestampMessageImprint(TimestampWrapper contentTimestamp) {
		LevelRule constraint = validationPolicy.getContentTimeStampMessageImprintConstraint(context);
		return new TimestampMessageImprintWithIdCheck<>(i18nProvider, result, contentTimestamp, constraint);
	}

	private ChainItem<XmlSAV> claimedRoles() {
		MultiValuesRule constraint = validationPolicy.getClaimedRoleConstraint(context);
		return new ClaimedRolesCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> certifiedRoles() {
		MultiValuesRule constraint = validationPolicy.getCertifiedRolesConstraint(context);
		return new CertifiedRolesCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> counterSignature() {
		LevelRule constraint = validationPolicy.getCounterSignatureConstraint(context);
		return new CounterSignatureCheck(i18nProvider, result, diagnosticData, token, constraint);
	}

	private ChainItem<XmlSAV> signatureTimeStamp() {
		LevelRule constraint = validationPolicy.getSignatureTimeStampConstraint(context);
		return new SignatureTimeStampCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> validationDataTimeStamp() {
		LevelRule constraint = validationPolicy.getValidationDataTimeStampConstraint(context);
		return new ValidationDataTimeStampCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> validationDataRefsOnlyTimeStamp() {
		LevelRule constraint = validationPolicy.getValidationDataRefsOnlyTimeStampConstraint(context);
		return new ValidationDataRefsOnlyTimeStampCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> archiveTimeStamp() {
		LevelRule constraint = validationPolicy.getArchiveTimeStampConstraint(context);
		return new ArchiveTimeStampCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> documentTimeStamp() {
		LevelRule constraint = validationPolicy.getDocumentTimeStampConstraint(context);
		return new DocumentTimeStampCheck(i18nProvider, result, token, constraint);
	}

	private LevelRule getTimestampBasicValidationConstraintLevel() {
		LevelRule constraint = validationPolicy.getTimestampValidConstraint();
		// continue if LTA is present
		if (constraint == null || ValidationProcessUtils.isLongTermAvailabilityAndIntegrityMaterialPresent(token)) {
			constraint = getWarnLevelRule();
		}
		return constraint;
	}

	@Override
	protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
		if (XmlBlockType.TST_BBB.equals(constraint.getBlockType()) &&
				(validationPolicy.getTimestampValidConstraint() == null || ValidationProcessUtils.isLongTermAvailabilityAndIntegrityMaterialPresent(token))) {
			// skip validation messages for content TSTs
		} else {
			super.collectMessages(conclusion, constraint);
		}
	}

}
