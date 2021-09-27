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
package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AcceptableMimetypeFileContentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AcceptableZipCommentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AllFilesSignedCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ContainerTypeCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.DocMDPCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FieldMDPCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FormatCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FullScopeCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ManifestFilePresentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.MimeTypeFilePresentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PdfAnnotationOverlapCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PdfPageDifferenceCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PdfVisualDifferenceCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ReferencesNotAmbiguousCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SigFieldLockCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignatureNotAmbiguousCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignedFilesPresentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignerInformationStoreCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.UndefinedChangesCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ZipCommentPresentCheck;

/**
 * 5.2.2 Format Checking
 * 
 * This building block shall check that the signature to validate is conformant
 * to the applicable base format (e.g. CMS [i.8], CAdES [i.2], XML-DSig [i.11],
 * XAdES [i.4], etc.) prior to any subsequent processing.
 */
public class FormatChecking extends Chain<XmlFC> {

	/** Diagnostic data */
	private final DiagnosticData diagnosticData;

	/** The signature to validate */
	private final SignatureWrapper signature;

	/** The validation context */
	private final Context context;

	/** The validation policy */
	private final ValidationPolicy policy;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param signature {@link SignatureWrapper}
	 * @param context {@link Context}
	 * @param policy {@link ValidationPolicy}
	 */
	public FormatChecking(I18nProvider i18nProvider, DiagnosticData diagnosticData, SignatureWrapper signature,
						  Context context, ValidationPolicy policy) {
		super(i18nProvider, new XmlFC());
		this.diagnosticData = diagnosticData;
		this.signature = signature;
		this.context = context;
		this.policy = policy;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.FORMAT_CHECKING;
	}

	@Override
	protected void initChain() {
		ChainItem<XmlFC> item = firstItem = formatCheck();
		
		item = item.setNextItem(signatureDuplicateCheck());

		item = item.setNextItem(referenceDuplicateCheck());

		item = item.setNextItem(fullScopeCheck());
		
		// PAdES only
		if (signature.getPDFRevision() != null) {
			
			item = item.setNextItem(signerInformationStoreCheck());
			
			item = item.setNextItem(pdfPageDifferenceCheck());
			
			item = item.setNextItem(pdfAnnotationOverlapCheck());
			
			item = item.setNextItem(pdfVisualDifferenceCheck());;

			// /DocMDP check
			if (signature.getDocMDPPermissions() != null) {
				item = item.setNextItem(docMDPCheck());
			}
			// /FieldMDP
			if (signature.getFieldMDP() != null) {
				item = item.setNextItem(fieldMDPCheck());
			}
			// /SigFieldLock
			if (signature.getSigFieldLock() != null) {
				item = item.setNextItem(sigFieldLockCheck());
			}

			item = item.setNextItem(undefinedChangesCheck());
			
		}

		if (diagnosticData.isContainerInfoPresent()) {

			item = item.setNextItem(containerTypeCheck());

			item = item.setNextItem(zipCommentPresentCheck());

			item = item.setNextItem(acceptableZipCommentCheck());

			item = item.setNextItem(mimetypeFilePresentCheck());

			item = item.setNextItem(mimetypeFileContentCheck());

			item = item.setNextItem(manifestFilePresentCheck());

			item = item.setNextItem(signedFilesPresentCheck());
			
			item = item.setNextItem(allFilesSignedCheck());
			
		}
		
	}

	private ChainItem<XmlFC> formatCheck() {
		MultiValuesConstraint constraint = policy.getSignatureFormatConstraint(context);
		return new FormatCheck(i18nProvider, result, signature, constraint);
	}
	
	private ChainItem<XmlFC> signatureDuplicateCheck() {
		LevelConstraint constraint = policy.getSignatureDuplicatedConstraint(context);
		return new SignatureNotAmbiguousCheck(i18nProvider, result, signature, constraint);
	}

	private ChainItem<XmlFC> referenceDuplicateCheck() {
		return new ReferencesNotAmbiguousCheck(i18nProvider, result, signature, getFailLevelConstraint());
	}

	private ChainItem<XmlFC> fullScopeCheck() {
		LevelConstraint constraint = policy.getFullScopeConstraint();
		return new FullScopeCheck(i18nProvider, result, signature, constraint);
	}
	
	private ChainItem<XmlFC> signerInformationStoreCheck() {
		LevelConstraint constraint = policy.getSignerInformationStoreConstraint(context);
		return new SignerInformationStoreCheck(i18nProvider, result, signature, constraint);
	}
	
	private ChainItem<XmlFC> pdfPageDifferenceCheck() {
		LevelConstraint constraint = policy.getPdfPageDifferenceConstraint(context);
		return new PdfPageDifferenceCheck(i18nProvider, result, signature, constraint);
	}
	
	private ChainItem<XmlFC> pdfAnnotationOverlapCheck() {
		LevelConstraint constraint = policy.getPdfAnnotationOverlapConstraint(context);
		return new PdfAnnotationOverlapCheck(i18nProvider, result, signature, constraint);
	}
	
	private ChainItem<XmlFC> pdfVisualDifferenceCheck() {
		LevelConstraint constraint = policy.getPdfVisualDifferenceConstraint(context);
		return new PdfVisualDifferenceCheck(i18nProvider, result, signature, constraint);
	}

	private ChainItem<XmlFC> docMDPCheck() {
		LevelConstraint constraint = policy.getDocMDPConstraint(context);
		return new DocMDPCheck(i18nProvider, result, signature, constraint);
	}

	private ChainItem<XmlFC> fieldMDPCheck() {
		LevelConstraint constraint = policy.getFieldMDPConstraint(context);
		return new FieldMDPCheck(i18nProvider, result, signature, constraint);
	}

	private ChainItem<XmlFC> sigFieldLockCheck() {
		LevelConstraint constraint = policy.getSigFieldLockConstraint(context);
		return new SigFieldLockCheck(i18nProvider, result, signature, constraint);
	}

	private ChainItem<XmlFC> undefinedChangesCheck() {
		LevelConstraint constraint = policy.getUndefinedChangesConstraint(context);
		return new UndefinedChangesCheck(i18nProvider, result, signature, constraint);
	}

	private ChainItem<XmlFC> containerTypeCheck() {
		MultiValuesConstraint constraint = policy.getAcceptedContainerTypesConstraint();
		return new ContainerTypeCheck(i18nProvider, result, diagnosticData.getContainerType(), constraint);
	}

	private ChainItem<XmlFC> zipCommentPresentCheck() {
		LevelConstraint constraint = policy.getZipCommentPresentConstraint();
		return new ZipCommentPresentCheck(i18nProvider, result, diagnosticData.getZipComment(), constraint);
	}

	private ChainItem<XmlFC> acceptableZipCommentCheck() {
		MultiValuesConstraint constraint = policy.getAcceptedZipCommentsConstraint();
		return new AcceptableZipCommentCheck(i18nProvider, result, diagnosticData.getZipComment(), constraint);
	}

	private ChainItem<XmlFC> mimetypeFilePresentCheck() {
		LevelConstraint constraint = policy.getMimeTypeFilePresentConstraint();
		return new MimeTypeFilePresentCheck(i18nProvider, result, diagnosticData.isMimetypeFilePresent(), constraint);
	}

	private ChainItem<XmlFC> mimetypeFileContentCheck() {
		MultiValuesConstraint constraint = policy.getAcceptedMimeTypeContentsConstraint();
		return new AcceptableMimetypeFileContentCheck(i18nProvider, result, diagnosticData.getMimetypeFileContent(), constraint);
	}

	private ChainItem<XmlFC> manifestFilePresentCheck() {
		LevelConstraint constraint = policy.getManifestFilePresentConstraint();
		return new ManifestFilePresentCheck(i18nProvider, result, diagnosticData.getContainerInfo(), constraint);
	}

	private ChainItem<XmlFC> signedFilesPresentCheck() {
		LevelConstraint constraint = policy.getSignedFilesPresentConstraint();
		return new SignedFilesPresentCheck(i18nProvider, result, diagnosticData.getContainerInfo(), constraint);
	}

	private ChainItem<XmlFC> allFilesSignedCheck() {
		LevelConstraint constraint = policy.getAllFilesSignedConstraint();
		return new AllFilesSignedCheck(i18nProvider, result, signature, diagnosticData.getContainerInfo(), constraint);
	}

}
