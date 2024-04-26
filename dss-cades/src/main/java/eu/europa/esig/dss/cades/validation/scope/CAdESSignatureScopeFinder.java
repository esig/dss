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
package eu.europa.esig.dss.cades.validation.scope;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.scope.AbstractSignatureScopeFinder;
import eu.europa.esig.dss.validation.scope.ContainerContentSignatureScope;
import eu.europa.esig.dss.validation.scope.ContainerSignatureScope;
import eu.europa.esig.dss.validation.scope.CounterSignatureScope;
import eu.europa.esig.dss.validation.scope.DigestSignatureScope;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.ManifestSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Finds {@code SignatureScope}s for a CAdES signature
 */
public class CAdESSignatureScopeFinder extends AbstractSignatureScopeFinder implements SignatureScopeFinder<CAdESSignature> {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignatureScopeFinder.class);

    /**
     * Default constructor
     */
    public CAdESSignatureScopeFinder() {
        // empty
    }

    @Override
    public List<SignatureScope> findSignatureScope(final CAdESSignature cadesSignature) {
        DSSDocument originalDocument = getOriginalDocument(cadesSignature);
        if (originalDocument == null) {
            return Collections.emptyList();
        }

        final List<SignatureScope> result = new ArrayList<>();
        if (isASiCSArchive(cadesSignature)) {
            ContainerSignatureScope containerSignatureScope = new ContainerSignatureScope(originalDocument);
            result.add(containerSignatureScope);
            for (DSSDocument archivedDocument : cadesSignature.getContainerContents()) {
                containerSignatureScope.addChildSignatureScope(new ContainerContentSignatureScope(archivedDocument));
            }

        } else if (isASiCEArchive(cadesSignature)) {
            ManifestFile manifestFile = cadesSignature.getManifestFile();
            ManifestSignatureScope manifestSignatureScope = new ManifestSignatureScope(manifestFile);
            result.add(manifestSignatureScope);

            for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
                if (manifestEntry.isIntact()) {
                    DSSDocument referencedDocument = getReferencedDocument(manifestEntry, cadesSignature.getContainerContents());
                    manifestSignatureScope.addChildSignatureScope(
                            new FullSignatureScope(manifestEntry.getFileName(), referencedDocument));
                }
            }

        } else {
            List<ReferenceValidation> referenceValidations = cadesSignature.getReferenceValidations();
            if (Utils.isCollectionNotEmpty(referenceValidations)) {
                ReferenceValidation reference = referenceValidations.iterator().next(); // only one Reference is allowed in CAdES
                if (reference.isIntact()) {
                    return getSignatureScopeFromOriginalDocument(cadesSignature, originalDocument);
                } else if (reference.isFound()) {
                    return getSignatureScopeFromReferenceValidation(reference);
                }
            }

        }
        return result;
    }

    /**
     * Returns a list of {@code SignatureScope}s from the signed document
     *
     * @param cadesSignature {@link CAdESSignature}
     * @param originalDocument {@link DSSDocument}
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> getSignatureScopeFromOriginalDocument(final CAdESSignature cadesSignature,
                                                                         final DSSDocument originalDocument) {
        List<SignatureScope> result = new ArrayList<>();
        if (originalDocument == null) {
        	return result;
        }
        
        String fileName = originalDocument.getName();
        if (cadesSignature.isCounterSignature()) {
            return Collections.singletonList(new CounterSignatureScope(cadesSignature.getMasterSignature(), originalDocument));

        } else if (originalDocument instanceof DigestDocument) {
            DigestDocument digestDocument = (DigestDocument) originalDocument;
            result.add(new DigestSignatureScope(fileName != null ? fileName : "Digest document", digestDocument));

        } else {
            result.add(new FullSignatureScope(fileName != null ? fileName : "Full document", originalDocument));
        }
        
        return result;
    }

    /**
     * Gets a list of {@code SignatureScope}s from a {@code ReferenceValidation}
     *
     * @param reference {@link ReferenceValidation} to get SignatureScope from
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> getSignatureScopeFromReferenceValidation(ReferenceValidation reference) {
        List<SignatureScope> result = new ArrayList<>();
        DSSDocument digestDocument = createDigestDocument(reference.getDigest());
        if (digestDocument != null) {
            result.add(new FullSignatureScope("Full document", digestDocument));
        }
        return result;
    }
    
    /**
     * Returns original document for the given CAdES signature
     * @param cadesSignature {@link CAdESSignature} to get original document for
     * @return {@link DSSDocument} original document
     */
    protected DSSDocument getOriginalDocument(final CAdESSignature cadesSignature) {
    	try {
            return cadesSignature.getOriginalDocument();
        } catch (DSSException e) {
        	LOG.warn("A CAdES signer's original document is not found [{}].", e.getMessage());
        	return null;
        }
    }
    
    @Override
    protected boolean isASiCSArchive(AdvancedSignature advancedSignature) {
        return super.isASiCSArchive(advancedSignature) && !super.isASiCEArchive(advancedSignature);
    }

    /**
     * This method returns a document references from the {@code manifestEntry}
     *
     * @param manifestEntry {@link ManifestEntry} to get document for
     * @param detachedDocuments a list of {@link DSSDocument}s representing the ASiC's content
     * @return {@link DSSDocument}
     */
    protected DSSDocument getReferencedDocument(ManifestEntry manifestEntry, List<DSSDocument> detachedDocuments) {
        DSSDocument document = DSSUtils.getDocumentWithName(detachedDocuments, manifestEntry.getFileName());
        if (document == null) {
            document = createDigestDocument(manifestEntry.getDigest());
        }
        return document;
    }

}
