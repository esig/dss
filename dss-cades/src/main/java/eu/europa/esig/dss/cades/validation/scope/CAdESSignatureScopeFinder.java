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
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ReferenceValidation;
import eu.europa.esig.dss.validation.scope.AbstractSignatureScopeFinder;
import eu.europa.esig.dss.validation.scope.CounterSignatureScope;
import eu.europa.esig.dss.validation.scope.DigestSignatureScope;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Finds {@code SignatureScope}s for a CAdES signature
 */
public class CAdESSignatureScopeFinder extends AbstractSignatureScopeFinder<CAdESSignature> {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignatureScopeFinder.class);

    @Override
    public List<SignatureScope> findSignatureScope(final CAdESSignature cadesSignature) {
        List<ReferenceValidation> referenceValidations = cadesSignature.getReferenceValidations();
        if (Utils.isCollectionNotEmpty(referenceValidations)) {
        	ReferenceValidation reference = referenceValidations.iterator().next(); // only one Reference is allowed in CAdES
        	if (reference.isIntact()) {
                DSSDocument originalDocument = getOriginalDocument(cadesSignature);
                return getSignatureScopeFromOriginalDocument(cadesSignature, originalDocument);
        	} else if (reference.isFound()) {
                return getSignatureScopeFromReferenceValidation(reference);
        	}
        }
    	return Collections.emptyList();
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
    		return Collections.singletonList(new CounterSignatureScope(cadesSignature.getMasterSignature().getId(), 
    				getDigest(originalDocument) ));
    		
        } else if (originalDocument instanceof DigestDocument) {
        	DigestDocument digestDocument = (DigestDocument) originalDocument;
            result.add(new DigestSignatureScope(fileName != null ? fileName : "Digest document", 
            		digestDocument.getExistingDigest()));
            
        } else {
			result.add(new FullSignatureScope(fileName != null ? fileName : "Full document", 
					getDigest(originalDocument)));
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
		result.add(new FullSignatureScope("Full document", reference.getDigest()));
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
    
}
