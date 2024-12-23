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
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.signature.ProfileParameters;
import eu.europa.esig.dss.pdf.PdfSignatureCache;

import java.util.Objects;

/**
 * This class is used to accelerate signature creation process for PAdES.
 * The cache is set within {@code PAdESService.getDataToSign(...)} method and
 * used in {@code PAdESService.signDocument(...)} method.
 *
 */
public class PAdESProfileParameters extends ProfileParameters {

    private static final long serialVersionUID = 852030281057208148L;

    /**
     * Internal cache used to accelerate the signature creation process
     */
    private PdfSignatureCache pdfToBeSignedCache;

    /**
     * Default constructor
     */
    public PAdESProfileParameters() {
        // empty
    }

    /**
     * Gets the PDF signature cache
     *
     * @return {@link PdfSignatureCache}
     */
    public PdfSignatureCache getPdfToBeSignedCache() {
        if (pdfToBeSignedCache == null) {
            pdfToBeSignedCache = new PdfSignatureCache();
        }
        return pdfToBeSignedCache;
    }

    /**
     * Sets the PDF signature cache
     *
     * @param pdfToBeSignedCache {@link PdfSignatureCache}
     */
    public void setPdfToBeSignedCache(PdfSignatureCache pdfToBeSignedCache) {
        this.pdfToBeSignedCache = pdfToBeSignedCache;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        PAdESProfileParameters that = (PAdESProfileParameters) o;
        return Objects.equals(pdfToBeSignedCache, that.pdfToBeSignedCache);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Objects.hashCode(pdfToBeSignedCache);
        return result;
    }

    @Override
    public String toString() {
        return "PAdESProfileParameters [" +
                "pdfToBeSignedCache=" + pdfToBeSignedCache +
                "] " + super.toString();
    }

}
