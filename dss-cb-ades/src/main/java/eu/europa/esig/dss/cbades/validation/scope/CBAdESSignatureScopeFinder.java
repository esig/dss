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
package eu.europa.esig.dss.cbades.validation.scope;

import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.scope.AbstractSignatureScopeFinder;
import eu.europa.esig.dss.spi.validation.scope.CounterSignatureScope;
import eu.europa.esig.dss.spi.validation.scope.DigestSignatureScope;
import eu.europa.esig.dss.spi.validation.scope.AttestationSignatureScope;
import eu.europa.esig.dss.spi.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.spi.validation.scope.KeyBindingSignatureScope;
import eu.europa.esig.dss.spi.validation.scope.SignatureScopeFinder;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Finds a SignatureScope for a CB-AdES signature
 * 
 */
public class CBAdESSignatureScopeFinder extends AbstractSignatureScopeFinder implements SignatureScopeFinder<CBAdESSignature> {

    private static final Logger LOG = LoggerFactory.getLogger(CBAdESSignatureScopeFinder.class);

    /**
     * Default constructor
     */
    public CBAdESSignatureScopeFinder() {
        // empty
    }

    @Override
    public List<SignatureScope> findSignatureScope(final CBAdESSignature cbadesSignature) {
        List<SignatureScope> result = new ArrayList<>();

        List<DSSDocument> originalDocuments = getOriginalDocuments(cbadesSignature);
        if (Utils.isCollectionEmpty(originalDocuments)) {
            return result;
        }

        List<ReferenceValidation> referenceValidations = cbadesSignature.getReferenceValidations();
        for (int i = 0; i < referenceValidations.size(); i++) {
            ReferenceValidation referenceValidation = referenceValidations.get(i);
            if (referenceValidation.isIntact()) {
                if (cbadesSignature.isCounterSignature() && i == 0) {
                    AdvancedSignature masterSignature = cbadesSignature.getMasterSignature();
                    // first document shall always correspond to a counter signature signed value
                    result.add(new CounterSignatureScope(masterSignature, originalDocuments.get(0)));
                    if (COSESignatureType.COSE_SIGN1 == ((CBAdESSignature) masterSignature).getCOSESignatureType()) {
                        result.addAll(masterSignature.getSignatureScopes());
                    }
                    return result;

                } else if (cbadesSignature.isKeyBindingSignature()) {
                    // only one document shall be present
                    return Collections.singletonList(new KeyBindingSignatureScope(cbadesSignature.getAttestation(), originalDocuments.get(0)));

                } else if (cbadesSignature.getAttestation() != null) {
                    // only one document shall be present
                    return Collections.singletonList(new AttestationSignatureScope(cbadesSignature.getAttestation(), originalDocuments.get(0)));

                } else if (originalDocuments.size() == 1) {
                    return Collections.singletonList(getSignatureScopeFromOriginalDocument(originalDocuments.get(0)));

                } else if (referenceValidation.getUri() != null) {
                    DSSDocument document = referenceValidation.getDocument();
                    result.add(getSignatureScopeFromOriginalDocument(document));

                } else if (referenceValidations.size() == 1) {
                    return getSignatureScopeFromOriginalDocuments(originalDocuments);
                }

            }
        }

        return result;
    }

    /**
     * Returns original documents for the given CBAdES signature
     *
     * @param cbadesSignature {@link CBAdESSignature} to get original document for
     * @return a list of {@link DSSDocument}s original document
     */
    protected List<DSSDocument> getOriginalDocuments(final CBAdESSignature cbadesSignature) {
        try {
            return cbadesSignature.getOriginalDocuments();
        } catch (DSSException e) {
            LOG.warn("A CB-AdES signer's original document is not found [{}].", e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Returns a {@code SignatureScope} for the given {@code originalDocument}
     *
     * @param originalDocument {@link DSSDocument} to get a SignatureScope for
     * @return {@link SignatureScope}
     */
    protected SignatureScope getSignatureScopeFromOriginalDocument(DSSDocument originalDocument) {
        if (originalDocument instanceof DigestDocument) {
            DigestDocument digestDocument = (DigestDocument) originalDocument;
            return new DigestSignatureScope(originalDocument.getName(), digestDocument);

        } else {
            return new FullSignatureScope(originalDocument.getName(), originalDocument);
        }
    }

    /**
     * Extracts a SignatureScope list from a list of original documents
     *
     * @param originalDocuments a list of {@link DSSDocument} original documents
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> getSignatureScopeFromOriginalDocuments(List<DSSDocument> originalDocuments) {
        List<SignatureScope> result = new ArrayList<>();
        if (Utils.isCollectionEmpty(originalDocuments)) {
            return result;
        }

        for (DSSDocument originalDocument : originalDocuments) {
            String documentName = originalDocument.getName() != null ? originalDocument.getName() : "Detached content";
            if (originalDocument instanceof DigestDocument) {
                DigestDocument digestDocument = (DigestDocument) originalDocument;
                result.add(new DigestSignatureScope(documentName, digestDocument));

            } else {
                result.add(new FullSignatureScope(documentName, originalDocument));

            }
        }

        return result;
    }

}
