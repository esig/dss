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
package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.ArrayList;
import java.util.List;

/**
 * Checks if all files are signed inside an ASiC container
 */
public class AllFilesSignedCheck extends ChainItem<XmlFC> {

	/** The signature */
	private final SignatureWrapper signature;

	/** Container information */
	private final XmlContainerInfo containerInfo;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlFC}
	 * @param signature {@link SignatureWrapper}
	 * @param containerInfo {@link XmlContainerInfo}
	 * @param constraint {@link LevelConstraint}
	 */
	public AllFilesSignedCheck(I18nProvider i18nProvider, XmlFC result, SignatureWrapper signature,
							   XmlContainerInfo containerInfo, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.signature = signature;
		this.containerInfo = containerInfo;
	}

	@Override
	protected boolean process() {
		/* ASiC-S -> nb files = 1 */
		if (ASiCContainerType.ASiC_S.equals(containerInfo.getContainerType())) {
			return 1 == Utils.collectionSize(containerInfo.getContentFiles());

		} else if (ASiCContainerType.ASiC_E.equals(containerInfo.getContainerType())) {
			String signatureFilename = signature.getSignatureFilename();
			List<String> contentFiles = containerInfo.getContentFiles();

			XmlManifestFile manifestFile = getRelatedManifestFile(signatureFilename);
			if (manifestFile != null) {
				List<String> coveredFiles = manifestFile.getEntries();
				// check manifest <> content
				if (!coversAllOriginalFiles(coveredFiles, contentFiles)) {
					return false;
				}
			} else if (SignatureForm.CAdES.equals(signature.getSignatureFormat().getSignatureForm())) {
				// CAdES -> manifest file shall be present and signed
				return false;
			}

			// XAdES -> check signature scope
			if (SignatureForm.XAdES.equals(signature.getSignatureFormat().getSignatureForm())) {
				List<String> coveredFilesFromScope = getCoveredFilesFromScope();
				return coversAllOriginalFiles(coveredFilesFromScope, contentFiles);
			}

			return true;
		}

		return false;
	}

	private boolean coversAllOriginalFiles(List<String> coveredFiles, List<String> originalFiles) {
		for (String file : originalFiles) {
			if (!coveredFiles.contains(file)) {
				return false;
			}
		}
		return true;
	}

	private XmlManifestFile getRelatedManifestFile(String signatureFilename) {
		List<XmlManifestFile> manifestFiles = containerInfo.getManifestFiles();
		for (XmlManifestFile xmlManifestFile : manifestFiles) {
			if (Utils.areStringsEqual(signatureFilename, xmlManifestFile.getSignatureFilename())) {
				return xmlManifestFile;
			}
		}
		return null;
	}

	private List<String> getCoveredFilesFromScope() {
		List<String> result = new ArrayList<>();
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		for (XmlSignatureScope xmlSignatureScope : signatureScopes) {
			if (SignatureScopeType.FULL == xmlSignatureScope.getScope()) {
				result.add(xmlSignatureScope.getName());
			}
		}
		return result;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_CV_IAFS;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_CV_IAFS_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.FORMAT_FAILURE;
	}

}
