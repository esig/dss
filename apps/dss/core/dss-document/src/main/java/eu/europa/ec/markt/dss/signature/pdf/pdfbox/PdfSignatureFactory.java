/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfDocTimestampInfo;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureInfo;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class PdfSignatureFactory {

    // dependency to pdfbox/PDDocument is just for building inner object and pdf object can be closed after
    public static PdfSignatureInfo createPdfSignatureInfo(CertificatePool validationCertPool, PdfDict outerCatalog, PDDocument doc, PDSignature signature, byte[] cms,
                                                          ByteArrayOutputStream buffer) throws IOException {
        return new PdfBoxSignatureInfo(validationCertPool, outerCatalog, doc, signature, cms, new ByteArrayInputStream(buffer.toByteArray()));
    }

    // dependency to pdfbox/PDDocument is just for building inner object and pdf object can be closed after
    public static PdfDocTimestampInfo createPdfTimestampInfo(CertificatePool validationCertPool, PdfDict outerCatalog, PDDocument doc, PDSignature signature, byte[] cms,
                                                             ByteArrayOutputStream buffer) throws IOException {
        return new PdfBoxDocTimestampInfo(validationCertPool, outerCatalog, doc, signature, cms, new ByteArrayInputStream(buffer.toByteArray()));
    }

}
