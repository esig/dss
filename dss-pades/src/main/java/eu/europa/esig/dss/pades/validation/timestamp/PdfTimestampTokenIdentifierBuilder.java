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
package eu.europa.esig.dss.pades.validation.timestamp;

import eu.europa.esig.dss.pades.validation.PdfSignatureField;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.spi.x509.tsp.TimestampIdentifierBuilder;

/**
 * Builds an {@code eu.europa.esig.dss.spi.x509.tsp.TimestampTokenIdentifier}
 * for a {@code eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken}
 *
 */
public class PdfTimestampTokenIdentifierBuilder extends TimestampIdentifierBuilder {

    private static final long serialVersionUID = -6655656136412456482L;

    /**
     * PDF document time-stamp token
     */
    private final PdfTimestampToken pdfTimestampToken;

    /**
     * Default constructor to build an identifier for a {@code PdfTimestampToken}
     *
     * @param pdfTimestampToken {@link PdfTimestampToken}
     */
    public PdfTimestampTokenIdentifierBuilder(final PdfTimestampToken pdfTimestampToken) {
        super(pdfTimestampToken.getEncoded());
        this.pdfTimestampToken = pdfTimestampToken;
    }

    @Override
    protected String getTimestampPosition() {
        StringBuilder stringBuilder = new StringBuilder();
        PdfDocTimestampRevision pdfRevision = pdfTimestampToken.getPdfRevision();
        for (PdfSignatureField signatureField : pdfRevision.getFields()) {
            stringBuilder.append(signatureField.getFieldName());
        }
        return stringBuilder.toString();
    }

}
