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
package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class AllFilesSignedCheck extends ChainItem<XmlCV> {

	private final SignatureWrapper signature;
	private final XmlContainerInfo containerInfo;

	public AllFilesSignedCheck(XmlCV result, SignatureWrapper signature, XmlContainerInfo containerInfo, LevelConstraint constraint) {
		super(result, constraint);
		this.signature = signature;
		this.containerInfo = containerInfo;
	}

	@Override
	protected boolean process() {

		/* ASiC-S -> nb files = 1 */
		if ("ASiC-S".equals(containerInfo.getContainerType())) {
			return 1 == Utils.collectionSize(containerInfo.getContentFiles());
		} else if ("ASiC-E".equals(containerInfo.getContainerType())) {
			String signatureFilename = signature.getSignatureFilename();
			List<String> coveredFiles = getCoveredFilesBySignatureFilename(signatureFilename);
			List<String> contentFiles = containerInfo.getContentFiles();

			// check manifest <> content
			if (!sameContent(coveredFiles, contentFiles)) {
				return false;
			}

			// XAdES -> check signature scope
			if (signature.getFormat().startsWith("XAdES")) {
				List<String> coveredFilesFromScope = getCoveredFilesFromScope();
				return sameContent(coveredFilesFromScope, contentFiles);
			}

			// CAdES -> manifest file is signed
			return true;
		}

		return false;
	}

	private boolean sameContent(List<String> coveredFiles, List<String> contentFiles) {
		if (Utils.collectionSize(coveredFiles) == Utils.collectionSize(contentFiles)) {
			boolean findAll = true;

			for (String content : contentFiles) {
				findAll &= coveredFiles.contains(content);
			}

			if (findAll) {
				for (String covered : coveredFiles) {
					findAll &= contentFiles.contains(covered);
				}
			}

			return findAll;
		}
		return false;
	}

	private List<String> getCoveredFilesBySignatureFilename(String signatureFilename) {
		List<XmlManifestFile> manifestFiles = containerInfo.getManifestFiles();
		for (XmlManifestFile xmlManifestFile : manifestFiles) {
			if (Utils.areStringsEqual(signatureFilename, xmlManifestFile.getSignatureFilename())) {
				return xmlManifestFile.getEntries();
			}
		}
		return new ArrayList<String>();
	}

	private List<String> getCoveredFilesFromScope() {
		List<String> result = new ArrayList<String>();
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
		return SubIndication.SIG_CRYPTO_FAILURE;
	}

}
