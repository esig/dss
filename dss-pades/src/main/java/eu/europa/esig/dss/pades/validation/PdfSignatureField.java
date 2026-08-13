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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.SigFieldPermissions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Objects;

/**
 * Object of this interface represents a PDF Signature field
 *
 */
public class PdfSignatureField implements Serializable {

    private static final long serialVersionUID = 1391102373661984177L;

    private static final Logger LOG = LoggerFactory.getLogger(PdfSignatureField.class);

    /** Partial name of the signature field */
    private final String partialFieldName;

    /** Fully qualified name of the signature field */
    private final String fullyQualifiedName;

    /** The lock dictionary */
    private final SigFieldPermissions lockDictionary;

    /**
     * The signature field's dictionary.
     * Transient because {@code PdfDict} implementations are not {@code Serializable}
    */
    private final transient PdfDict dictionary;

    /**
     * Default constructor
     *
     * @param sigFieldDict {@link PdfDict}
     * @deprecated since DSS 6.6. Please use constructor
     *             {@code PdfSignatureField(PdfDict sigFieldDict, String fullyQualifiedName)} instead.
     */
    @Deprecated
    public PdfSignatureField(final PdfDict sigFieldDict) {
        this(sigFieldDict, null);
    }

    /**
     * Constructor with a fully qualified name
     *
     * @param sigFieldDict {@link PdfDict}
     * @param fullyQualifiedName {@link String}
     */
    public PdfSignatureField(final PdfDict sigFieldDict, final String fullyQualifiedName) {
        Objects.requireNonNull(sigFieldDict, "sigFieldDict cannot be null!");
        this.partialFieldName = extractPartialFieldName(sigFieldDict);
        this.fullyQualifiedName = fullyQualifiedName;
        this.lockDictionary = extractLockDictionary(sigFieldDict);
        this.dictionary = sigFieldDict;
    }

    private static String extractPartialFieldName(PdfDict sigFieldDict) {
        return sigFieldDict.getStringValue(PAdESConstants.FIELD_NAME_NAME);
    }

    private static SigFieldPermissions extractLockDictionary(PdfDict sigFieldDict) {
        PdfDict lock = sigFieldDict.getAsDict(PAdESConstants.LOCK_NAME);
        if (lock != null) {
            return PAdESUtils.extractPermissionsDictionary(lock);
        }
        return null;
    }

    /**
     * This method returns a signature's partial field name
     *
     * @return {@link String} name
     * @deprecated since DSS 6.6. Please use {@code #getPartialFieldName} instead.
     */
    @Deprecated
    public String getFieldName() {
        return partialFieldName;
    }

    /**
     * This method returns a signature's partial field name
     *
     * @return {@link String} name
     */
    public String getPartialFieldName() {
        return partialFieldName;
    }

    /**
     * This method returns a signature field's fully qualified name.
     *
     * @return {@link String} fully qualified name
     */
    public String getFullyQualifiedName() {
        if (fullyQualifiedName == null) {
            // TODO : remove log message after DSS 6.6
            LOG.warn("Fully qualified name is not defined for a field with partial name '{}'", partialFieldName);
        }
        return fullyQualifiedName;
    }

    /**
     * Returns a /Lock dictionary content, when present
     *
     * @return {@link SigFieldPermissions}
     */
    public SigFieldPermissions getLockDictionary() {
        return lockDictionary;
    }

    /**
     * Returns the signature field's dictionary
     *
     * @return {@link PdfDict}
     */
    public PdfDict getDictionary() {
        return dictionary;
    }

    @Override
    public String toString() {
        return "PdfSignatureField {" +"name=" + getFullyQualifiedName() + '}';
    }

}
