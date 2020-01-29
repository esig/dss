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
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ContainerTypeCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FormatCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FullScopeCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ManifestFilePresentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.MimeTypeFilePresentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignatureNotAmbiguousCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignerInformationStoreCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ZipCommentPresentCheck;

/**
 * 5.2.2 Format Checking
 * 
 * This building block shall check that the signature to validate is conformant
 * to the applicable base format (e.g. CMS [i.8], CAdES [i.2], XML-DSig [i.11],
 * XAdES [i.4], etc.) prior to any subsequent processing.
 */
public class FormatChecking extends Chain<XmlFC> {

	private final DiagnosticData diagnosticData;
	private final SignatureWrapper signature;

	private final Context context;
	private final ValidationPolicy policy;

	public FormatChecking(I18nProvider i18nProvider, DiagnosticData diagnosticData, SignatureWrapper signature, Context context, ValidationPolicy policy) {
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
		
		item = item.setNextItem(duplicateCheck());

		item = item.setNextItem(fullScopeCheck());
		
		// PAdES only
		if (signature.getPDFRevision() != null) {
			item = item.setNextItem(signerInformationStoreCheck());
		}

		if (diagnosticData.isContainerInfoPresent()) {

			item = item.setNextItem(containerTypeCheck());

			item = item.setNextItem(zipCommentPresentCheck());

			item = item.setNextItem(acceptableZipCommentCheck());

			item = item.setNextItem(mimetypeFilePresentCheck());

			item = item.setNextItem(mimetypeFileContentCheck());

			item = item.setNextItem(manifestFilePresentCheck());
		}
	}

	private ChainItem<XmlFC> formatCheck() {
		MultiValuesConstraint constraint = policy.getSignatureFormatConstraint(context);
		return new FormatCheck(i18nProvider, result, signature, constraint);
	}
	
	private ChainItem<XmlFC> duplicateCheck() {
		LevelConstraint constraint = policy.getSignatureDuplicatedConstraint(context);
		return new SignatureNotAmbiguousCheck(i18nProvider, result, signature, constraint);
	}

	private ChainItem<XmlFC> fullScopeCheck() {
		LevelConstraint constraint = policy.getFullScopeConstraint();
		return new FullScopeCheck(i18nProvider, result, signature, constraint);
	}
	
	private ChainItem<XmlFC> signerInformationStoreCheck() {
		LevelConstraint constraint = policy.getSignerInformationStoreConstraint(context);
		return new SignerInformationStoreCheck(i18nProvider, result, signature, constraint);
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

}
