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
package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.io.Serializable;
import java.util.Objects;

/**
 * Represents a DataTransferObject containing the required parameters for creation of a PAdES signature by enveloping
 * the externally provided CMS signature within computed PDF signature revision.
 * <p>
 * It's only possible to transfer an object by POST and REST.
 *
 */
public class PDFExternalSignDocumentDTO implements Serializable {

    private static final long serialVersionUID = 8643243141734642919L;

    /** The document to be signed */
    private RemoteDocument toSignDocument;

    /** The signature parameters DTO */
    private RemoteSignatureParameters parameters;

    /** The document to be signed */
    private RemoteDocument cmsDocument;

    /**
     * Empty constructor
     */
    public PDFExternalSignDocumentDTO() {
        // empty
    }

    /**
     * Default constructor
     *
     * @param toSignDocument {@link RemoteDocument} PDF document to be signed
     * @param parameters {@link RemoteSignatureParameters} set of driving parameters for PAdES signature creation
     * @param cmsDocument {@link RemoteDocument} CMS signature (CMSSignedData)
     */
    public PDFExternalSignDocumentDTO(RemoteDocument toSignDocument, RemoteSignatureParameters parameters,
                                      RemoteDocument cmsDocument) {
        this.toSignDocument = toSignDocument;
        this.parameters = parameters;
        this.cmsDocument = cmsDocument;
    }

    /**
     * Gets the document to be signed
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getToSignDocument() {
        return toSignDocument;
    }

    /**
     * Sets the document to be signed
     *
     * @param toSignDocument {@link RemoteDocument}
     */
    public void setToSignDocument(RemoteDocument toSignDocument) {
        this.toSignDocument = toSignDocument;
    }

    /**
     * Gets the signature creation parameters
     *
     * @return {@link RemoteSignatureParameters}
     */
    public RemoteSignatureParameters getParameters() {
        return parameters;
    }

    /**
     * Sets the signature creation parameters
     *
     * @param parameters {@link RemoteSignatureParameters}
     */
    public void setParameters(RemoteSignatureParameters parameters) {
        this.parameters = parameters;
    }

    /**
     * Gets the CMS signature document
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getCmsDocument() {
        return cmsDocument;
    }

    /**
     * Sets the CMS signature document
     *
     * @param cmsDocument {@link RemoteDocument}
     */
    public void setCmsDocument(RemoteDocument cmsDocument) {
        this.cmsDocument = cmsDocument;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PDFExternalSignDocumentDTO)) return false;
        PDFExternalSignDocumentDTO that = (PDFExternalSignDocumentDTO) o;
        return Objects.equals(toSignDocument, that.toSignDocument)
                && Objects.equals(parameters, that.parameters)
                && Objects.equals(cmsDocument, that.cmsDocument);
    }

    @Override
    public int hashCode() {
        return Objects.hash(toSignDocument, parameters, cmsDocument);
    }

    @Override
    public String toString() {
        return "PDFExternalSignDocumentDTO [toSignDocument=" + getToSignDocument() + ", parameters=" + getParameters() +
                ", cmsDocument=" + getCmsDocument() + "]";
    }

}
