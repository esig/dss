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
package eu.europa.esig.dss.asic.common.signature;

import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.ManifestFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * The class contains methods for document extraction in order to create a counter signature
 */
public abstract class ASiCCounterSignatureHelper {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCCounterSignatureHelper.class);

	/** The document representing an ASiC container */
	protected final DSSDocument asicContainer;

	/** Represents a cached instance of ASiC container extraction result */
	private ASiCExtractResult extractResult;

	/**
	 * The default constructor
	 *
	 * @param asicContainer {@link DSSDocument} representing an ASiC container
	 */
	protected ASiCCounterSignatureHelper(DSSDocument asicContainer) {
		this.asicContainer = asicContainer;
	} 
	
	/**
	 * Returns a file containing a signature with the given id
	 * 
	 * @param signatureId {@link String} id of a signature to extract a file with
	 * @return {@link DSSDocument} signature document containing a signature to be counter signed with a defined id
	 */
	public DSSDocument extractSignatureDocument(String signatureId) {
		if (!ASiCUtils.isZip(asicContainer)) {
			throw new IllegalInputException("The provided file shall be an ASiC container with signatures inside!");
		}
		List<DSSDocument> signatureDocuments = getSignatureDocuments();
		if (Utils.isCollectionEmpty(signatureDocuments)) {
			throw new IllegalInputException("No signatures found to be extended!");
		}

		for (DSSDocument signatureDocument : signatureDocuments) {
			if (containsSignatureToBeCounterSigned(signatureDocument, signatureId)) {
				checkCounterSignaturePossible(signatureDocument);
				return signatureDocument;
			}
		}
		throw new IllegalArgumentException(String.format("A signature with id '%s' has not been found!", signatureId));
	}

	/**
	 * Returns a list if signature documents from the container
	 * 
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignatureDocuments() {
		ASiCExtractResult extractResult = getASiCExtractResult();
		return extractResult.getSignatureDocuments();
	}
	
	/**
	 * Returns a list if detached documents for a signature with a given filename
	 * 
	 * @param signatureFilename {@link String} a signature filename
	 * @return a list of {@link DSSDocument}s
	 */
	protected abstract List<DSSDocument> getDetachedDocuments(String signatureFilename);
	
	/**
	 * Returns a related manifest file for a signature with the given filename
	 * NOTE: used for ASiC with CAdES only
	 * 
	 * @param signatureFilename {@link String} a signature filename
	 * @return {@link ManifestFile} representing a related manifest file
	 */
	public ManifestFile getManifestFile(String signatureFilename) {
		// not applicable by default
		return null;
	}

	/**
	 * Extracts the ASiC container content (documents)
	 *
	 * @return {@link ASiCExtractResult}
	 */
	protected ASiCExtractResult getASiCExtractResult() {
		if (extractResult == null) {
			AbstractASiCContainerExtractor extractor = getASiCContainerExtractor();
			extractResult = extractor.extract();
		}
		return extractResult;
	}
	
	/**
	 * Gets an ASiC container extractor relative to the current implementation
	 * 
	 * @return {@link AbstractASiCContainerExtractor}
	 */
	protected abstract AbstractASiCContainerExtractor getASiCContainerExtractor();

	/**
	 * Gets a Document Validator relative to the current implementation
	 * 
	 * @param signatureDocument {@link DSSDocument}
	 * @return {@link DocumentValidator}
	 */
	protected abstract DocumentValidator getDocumentValidator(DSSDocument signatureDocument);
	
	private boolean containsSignatureToBeCounterSigned(DSSDocument signatureDocument, String signatureId) {
		try {
			DocumentValidator validator = getDocumentValidator(signatureDocument);
			validator.setDetachedContents(getDetachedDocuments(signatureDocument.getName()));
			validator.setManifestFile(getManifestFile(signatureDocument.getName()));
			
			List<AdvancedSignature> signatures = validator.getSignatures();
			for (AdvancedSignature signature : signatures) {
				if (containsSignatureToBeCounterSigned(signature, signatureId)) {
					return true;
				}
			}
			
		} catch (Exception e) {
			String errorMessage = "Unable to verify a file with name '{}'. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, signatureDocument.getName(), e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, signatureDocument.getName(), e.getMessage());
			}
		}
		return false;
	}
	
	private boolean containsSignatureToBeCounterSigned(AdvancedSignature signature, String signatureId) {
		if (signatureId.equals(signature.getId()) || signatureId.equals(signature.getDAIdentifier())) {
			return true;
		}
		for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
			if (containsSignatureToBeCounterSigned(counterSignature, signatureId)) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * This method verifies if a signatureDocument can be counter signed
	 * Throws an exception when an extension is not possible
	 * 
	 * @param signatureDocument {@link DSSDocument} to verify
	 */
	protected void checkCounterSignaturePossible(DSSDocument signatureDocument) {
		// do nothing by default
	}
	
	/**
	 * Returns a list of all signature files with a replaced {@code updatedSignatureDocument}
	 * 
	 * @param updatedSignatureDocument {@link DSSDocument} a signature document to be updated in a list of signatures
	 * @return a list of {@link DSSDocument} signatures
	 */
	public List<DSSDocument> getUpdatedSignatureDocumentsList(DSSDocument updatedSignatureDocument) {
		List<DSSDocument> newSignaturesList = new ArrayList<>();
		for (DSSDocument signature : getSignatureDocuments()) {
			if (updatedSignatureDocument.getName().equals(signature.getName())) {
				newSignaturesList.add(updatedSignatureDocument);
			} else {
				newSignaturesList.add(signature);
			}
		}
		return newSignaturesList;
	}

}
