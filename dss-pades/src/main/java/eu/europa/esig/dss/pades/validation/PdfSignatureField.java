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

/**
 * Object of this interface represents a PDF Signature field
 *
 */
public class PdfSignatureField {

    /** Represents an extracted /Lock dictionary (optional) */
    private final PdfDict sigFieldDict;

    /**
     * Default constructor
     *
     * @param sigFieldDict {@link PdfDict}
     */
    public PdfSignatureField(final PdfDict sigFieldDict) {
        this.sigFieldDict = sigFieldDict;
    }

    /**
     * This method returns a signature field's name
     *
     * @return {@link String} name
     */
    public String getFieldName() {
        return sigFieldDict.getStringValue(PAdESConstants.FIELD_NAME_NAME);
    }

    /**
     * Returns a /Lock dictionary content, when present
     *
     * @return {@link SigFieldPermissions}
     */
    public SigFieldPermissions getLockDictionary() {
        PdfDict lock = sigFieldDict.getAsDict(PAdESConstants.LOCK_NAME);
        if (lock != null) {
            return PAdESUtils.extractPermissionsDictionary(lock);
        }
        return null;
    }

    @Override
    public String toString() {
        return "PdfSignatureField {" +"name=" + getFieldName() + '}';
    }

}
