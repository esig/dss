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
package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AllFilesSignedCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.EllipticCurveKeySizeCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FormatCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FullScopeCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ReferencesNotAmbiguousCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignatureFilenameAdherenceCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignatureManifestFilenameAdherenceCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignatureNotAmbiguousCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignerInformationStoreCheck;

/**
 * 5.2.2 Format Checking
 * 
 * This building block shall check that the signature to validate is conformant
 * to the applicable base format (e.g. CMS [i.8], CAdES [i.2], XML-DSig [i.11],
 * XAdES [i.4], etc.) prior to any subsequent processing.
 */
public class SignatureFormatChecking extends AbstractFormatChecking<SignatureWrapper> {

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param signature {@link SignatureWrapper}
	 * @param context {@link Context}
	 * @param policy {@link ValidationPolicy}
	 */
	public SignatureFormatChecking(I18nProvider i18nProvider, DiagnosticData diagnosticData,
								   SignatureWrapper signature, Context context, ValidationPolicy policy) {
		super(i18nProvider, diagnosticData, signature, context, policy);
	}

	@Override
	protected void initChain() {

		ChainItem<XmlFC> item = firstItem = formatCheck();
		
		item = item.setNextItem(signatureDuplicateCheck());

		item = item.setNextItem(referenceDuplicateCheck());

		item = item.setNextItem(fullScopeCheck());
		
		// PAdES
		if (token.getPDFRevision() != null) {
			
			item = item.setNextItem(signerInformationStoreCheck());

			item = getPDFRevisionValidationChain(item);
			
		}

		// PDF/A
		if (diagnosticData.isPDFAValidationPerformed()) {

			item = getPdfaValidationChain(item);

		}

		// JAdES
		if (SignatureForm.JAdES.equals(token.getSignatureFormat().getSignatureForm())) {

			if (token.getEncryptionAlgorithm() != null && token.getEncryptionAlgorithm().isEquivalent(EncryptionAlgorithm.ECDSA)) {
				item = item.setNextItem(ellipticCurveKeySizeCheck());
			}

		}

		// ASiC
		if (diagnosticData.isContainerInfoPresent()) {

			item = getASiCContainerValidationChain(item);

			item = item.setNextItem(allFilesSignedCheck());
			
		}
		
	}

	private ChainItem<XmlFC> formatCheck() {
		MultiValuesRule constraint = policy.getSignatureFormatConstraint(context);
		return new FormatCheck(i18nProvider, result, token, constraint);
	}
	
	private ChainItem<XmlFC> signatureDuplicateCheck() {
		LevelRule constraint = policy.getSignatureDuplicatedConstraint(context);
		return new SignatureNotAmbiguousCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlFC> referenceDuplicateCheck() {
		return new ReferencesNotAmbiguousCheck(i18nProvider, result, token, getFailLevelRule());
	}

	private ChainItem<XmlFC> fullScopeCheck() {
		LevelRule constraint = policy.getFullScopeConstraint();
		return new FullScopeCheck(i18nProvider, result, token.getSignatureScopes(), constraint);
	}
	
	private ChainItem<XmlFC> signerInformationStoreCheck() {
		LevelRule constraint = policy.getSignerInformationStoreConstraint(context);
		return new SignerInformationStoreCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlFC> ellipticCurveKeySizeCheck() {
		LevelRule constraint = policy.getEllipticCurveKeySizeConstraint(context);
		return new EllipticCurveKeySizeCheck(i18nProvider, result, token, constraint);
	}

	@Override
	protected ChainItem<XmlFC> filenameAdherenceCheck() {
		LevelRule constraint = policy.getFilenameAdherenceConstraint();
		return new SignatureFilenameAdherenceCheck(i18nProvider, result, diagnosticData, token, constraint);
	}

	@Override
	protected ChainItem<XmlFC> manifestFilenameAdherenceCheck() {
		LevelRule constraint = policy.getFilenameAdherenceConstraint();
		return new SignatureManifestFilenameAdherenceCheck(i18nProvider, result, diagnosticData, token, constraint);
	}

	private ChainItem<XmlFC> allFilesSignedCheck() {
		LevelRule constraint = policy.getAllFilesSignedConstraint();
		return new AllFilesSignedCheck(i18nProvider, result, token, diagnosticData.getContainerInfo(), constraint);
	}

}
