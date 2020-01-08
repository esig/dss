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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.validation.PdfRevision;

/**
 * Use this callback to be called only for Signatures, not for Doc Timestamp
 *
 */
public abstract class PdfSignatureValidationCallback implements SignatureValidationCallback {

    @Override
    public void validate(PdfRevision pdfRevision) {
        if (pdfRevision instanceof PdfSignatureRevision) {
            PdfSignatureRevision signatureRevision = (PdfSignatureRevision) pdfRevision;
            validate(signatureRevision);
        }

    }

    public abstract void validate(PdfSignatureRevision pdfSignatureRevision);
}
