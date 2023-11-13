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
package eu.europa.esig.dss.xades.dataobject;

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xml.utils.DomUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Builds {@code eu.europa.esig.dss.xades.dataobject.DSSDataObjectFormat} objects.
 * The class handles the cases when a DataObjectFormat is not required to be created (e.g. in case of a counter-signature).
 *
 */
public class DataObjectFormatBuilder {

    /**
     * Collection of references to build DataObjectFormat objects based on
     */
    private Collection<DSSReference> references;

    /**
     * Empty constructor
     */
    public DataObjectFormatBuilder() {
        // empty
    }

    /**
     * Sets references to be used as a base for DataObjectFormat objects building
     *
     * @param references a collection of {@link DSSReference}s
     * @return this {@link DataObjectFormatBuilder}
     */
    public DataObjectFormatBuilder setReferences(Collection<DSSReference> references) {
        this.references = references;
        return this;
    }

    /**
     * This method builds a collection {@code DSSDataObjectFormat}s corresponding to the provided configuration.
     *
     * @return list of {@link DSSDataObjectFormat}s
     */
    public List<DSSDataObjectFormat> build() {
        if (Utils.isCollectionEmpty(references)) {
            return Collections.emptyList();
        }
        final List<DSSDataObjectFormat> result = new ArrayList<>();
        for (DSSReference reference : references) {
            if (DSSXMLUtils.isCounterSignatureReferenceType(reference.getType())) {
                /*
                 * 6.3 Requirements on XAdES signature's elements, qualifying properties and services
                 *
                 * k) Requirement for DataObjectFormat. One DataObjectFormat shall be generated for each signed data
                 * object, except the SignedProperties element, and except if the signature is a baseline signature
                 * countersigning a signature. If the signature is a baseline signature countersigning another signature, and if it
                 * only signs its own signed properties and the countersigned signature, then it shall not include any
                 * DataObjectFormat signed property. If the signature is a baseline signature countersigning another signature
                 * and if it signs its own signed properties, the countersigned signature, and other data object(s), then it shall
                 * include one DataObjectFormat signed property for each of these other signed data object(s) aforementioned.
                 */
                continue;
            }
            result.add(toDataObjectFormat(reference));
        }
        return result;
    }

    /**
     * This method creates a {@code DSSDataObjectFormat} based on the given {@code DSSReference} object
     * to be incorporated to the signature
     *
     * @param reference {@link DSSReference}
     * @return {@link DSSDataObjectFormat}
     */
    protected DSSDataObjectFormat toDataObjectFormat(DSSReference reference) {
        Objects.requireNonNull(reference, "Reference cannot be null!");
        final DSSDataObjectFormat dataObjectFormat = new DSSDataObjectFormat();
        if (Utils.isStringNotEmpty(reference.getId())) {
            dataObjectFormat.setObjectReference(DomUtils.toElementReference(reference.getId()));
        }
        dataObjectFormat.setMimeType(getReferenceMimeType(reference));
        return dataObjectFormat;
    }

    /**
     * This method returns the mimetype String of the given reference
     *
     * @param reference the reference to get mimetype for
     * @return the mime-type {@code String} of the reference or the default value {@code MimeTypeEnum.BINARY}
     */
    private String getReferenceMimeType(final DSSReference reference) {
        MimeType dataObjectFormatMimeType = MimeTypeEnum.BINARY;
        DSSDocument content = reference.getContents();
        if (content != null && content.getMimeType() != null) {
            dataObjectFormatMimeType = content.getMimeType();
        }
        return dataObjectFormatMimeType.getMimeTypeString();
    }

}
