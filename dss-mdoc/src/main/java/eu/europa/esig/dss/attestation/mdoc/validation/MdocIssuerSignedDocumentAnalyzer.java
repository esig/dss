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
package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.attestation.mdoc.IssuerSignedParser;
import eu.europa.esig.dss.attestation.mdoc.MdocUtils;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocIssuerSignedItem;
import eu.europa.esig.dss.attestation.mdoc.model.MdocIssuerSigned;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.enumerations.AttestationDocumentFormat;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class is used to parse and process attestation represented by an mdoc IssuerSigned object
 *
 */
public class MdocIssuerSignedDocumentAnalyzer extends AbstractMdocDocumentAnalyzer {

    /** Cached instance of the IssuerSigned */
    private MdocIssuerSigned issuerSigned;

    /**
     * Default constructor
     */
    public MdocIssuerSignedDocumentAnalyzer() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} to validate
     */
    public MdocIssuerSignedDocumentAnalyzer(DSSDocument document) {
        super(document);
        this.issuerSigned = buildIssuerSigned();
    }

    /**
     * Constructor with a parsed {@code MdocIssuerSigned}
     *
     * @param document {@link DSSDocument} to validate
     * @param issuerSigned {@link MdocIssuerSigned}
     */
    public MdocIssuerSignedDocumentAnalyzer(DSSDocument document, MdocIssuerSigned issuerSigned) {
        super(document);
        Objects.requireNonNull(document, "MdocIssuerSigned cannot be null!");
        this.issuerSigned = issuerSigned;
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        return new IssuerSignedParser(document).isSupported();
    }

    private MdocIssuerSigned buildIssuerSigned() {
        return new IssuerSignedParser(document).parse();
    }

    @Override
    protected MdocAttestationPresentation buildAttestationPresentation() {
        MdocAttestationPresentation mdocAttestationPresentation = new MdocAttestationPresentation();
        mdocAttestationPresentation.setAttestationPresentationType(AttestationDocumentFormat.MDOC_ISSUER_SIGNED);
        MdocAttestation mdocAttestation = MdocAttestation.initBuilder()
                .setSignatures(Collections.singletonList(getSignature()))
                .setDisclosures(getSignedItems())
                .setFilename(document.getName())
                .build();
        mdocAttestationPresentation.setElectronicAttestationsOfAttributes(Collections.singletonList(mdocAttestation));
        return mdocAttestationPresentation;
    }

    /**
     * Gets a list of signatures extracted from an 'issuerSigned'/'issuerAuth' header of a Document object.
     * NOTE: The ISO 18013-5 specifies that a COSE_Sign1 structure shall be used, thus only one signature is expected.
     *
     * @return {@link CBAdESSignature}
     */
    protected CBAdESSignature getSignature() {
        COSESignStructure issuerAuth = issuerSigned.getIssuerAuth();
        return getCoseSignature(issuerAuth);
    }

    /**
     * Returns a list of disclosures extracted for every namespace from a Document structure
     *
     * @return a list of {@link SelectiveDisclosure}s
     */
    protected List<SelectiveDisclosure> getSignedItems() {
        List<MdocIssuerSignedItem> selectiveDisclosures = MdocUtils.getSelectiveDisclosures(issuerSigned.getNamespaces());
        if (Utils.isCollectionNotEmpty(selectiveDisclosures)) {
            return new ArrayList<>(selectiveDisclosures);
        }
        return Collections.emptyList();
    }

}
