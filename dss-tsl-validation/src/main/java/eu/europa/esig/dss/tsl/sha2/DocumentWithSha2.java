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
package eu.europa.esig.dss.tsl.sha2;

import eu.europa.esig.dss.model.CommonDocument;
import eu.europa.esig.dss.model.DSSDocument;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * This class is used to represent a downloaded {@code eu.europa.esig.dss.model.DSSDocument}
 * with its corresponding ".sha2" file
 *
 */
public class DocumentWithSha2 extends CommonDocument {

    private static final long serialVersionUID = -6370847348735932510L;

    /** The original downloaded document */
    private final DSSDocument document;

    /** The corresponding sha2 document, containing digests of the {@code document} */
    private final DSSDocument sha2Document;

    /** List of errors occurred during .sha2 document processing */
    private List<String> errors;

    /**
     * Default constructor
     *
     * @param document {@link DSSDocument} original downloaded document
     * @param sha2Document {@link DSSDocument} corresponding sha2 document, containing digests of the {@code document}
     */
    protected DocumentWithSha2(final DSSDocument document, final DSSDocument sha2Document) {
        this.document = document;
        this.sha2Document = sha2Document;
    }

    /**
     * Gets the original document
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getDocument() {
        return document;
    }

    /**
     * Gets the downloaded sha2 document corresponding to the {@code document}
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getSha2Document() {
        return sha2Document;
    }

    /**
     * This method adds an error message occurred during the .sha2 file validation
     *
     * @param errorMessage {@link String} error
     */
    protected void addErrorMessage(String errorMessage) {
        getErrors().add(errorMessage);
    }

    /**
     * Returns a list of errors occurred during processing of .sha2 document.
     * Returns NULL if validation succeeded.
     *
     * @return a list of {@link String} errors, if any
     */
    public List<String> getErrors() {
        if (errors == null) {
            errors = new ArrayList<>();
        }
        return errors;
    }

    @Override
    public InputStream openStream() {
        Objects.requireNonNull(document, "Document is null! Unable to open InputStream.");
        return document.openStream();
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        if (!super.equals(object)) return false;

        DocumentWithSha2 that = (DocumentWithSha2) object;
        return Objects.equals(document, that.document)
                && Objects.equals(sha2Document, that.sha2Document)
                && Objects.equals(errors, that.errors);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Objects.hashCode(document);
        result = 31 * result + Objects.hashCode(sha2Document);
        result = 31 * result + Objects.hashCode(errors);
        return result;
    }

}
