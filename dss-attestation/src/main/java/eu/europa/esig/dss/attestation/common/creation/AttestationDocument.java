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
package eu.europa.esig.dss.attestation.common.creation;

import eu.europa.esig.dss.model.CommonDocument;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;

import java.io.InputStream;
import java.util.List;
import java.util.Objects;

/**
 * Represents an attestation with selective disclosures document.
 * The class allows extraction of SD Attestation parts, such as a signed attestation or selective disclosures only.
 *
 * @param <D>
 *         implementation of selective disclosure for the given attestation format
 */
public abstract class AttestationDocument<D extends SelectiveDisclosure> extends CommonDocument  {

    private static final long serialVersionUID = 2468430085298606741L;

    /** Attestation with selective disclosures document */
    private final DSSDocument document;

    /** Signed attestation document (SDs omitted) */
    private final DSSDocument signedAttestation;

    /** List of selective disclosures */
    private final List<D> selectiveDisclosures;

    /**
     * Default constructor, instantiating the object from a complete SD Attestation,
     * signed attestation and selective disclosures parts.
     *
     * @param document {@link DSSDocument} attestation document with selective disclosures
     * @param signedAttestation {@link DSSDocument} signed attestation (SDs omitted)
     * @param selectiveDisclosures a list of {@link SelectiveDisclosure}s, if any
     */
    protected AttestationDocument(final DSSDocument document, final DSSDocument signedAttestation,
                                  final List<D> selectiveDisclosures) {
        Objects.requireNonNull(document, "SD Attestation cannot be null!");
        this.document = document;
        this.signedAttestation = signedAttestation;
        this.selectiveDisclosures = selectiveDisclosures;
    }

    /**
     * Gets the signed attestation (usually a signature), with selective disclosures omitted.
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getSignedAttestation() {
        return signedAttestation;
    }

    /**
     * Gets a list of selective disclosures, if any
     *
     * @return a list of {@link SelectiveDisclosure}s
     */
    public List<D> getSelectiveDisclosures() {
        return selectiveDisclosures;
    }

    @Override
    public InputStream openStream() {
        return document.openStream();
    }

}
