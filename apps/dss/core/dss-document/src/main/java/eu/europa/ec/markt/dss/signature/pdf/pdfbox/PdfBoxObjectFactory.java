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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PDFTimestampService;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.pdf.PdfReader;
import eu.europa.ec.markt.dss.signature.pdf.PdfStream;
import eu.europa.ec.markt.dss.signature.pdf.PdfWriter;

public class PdfBoxObjectFactory extends PdfObjFactory {

    @Override
    public PdfArray newArray() {
        return new PdfBoxArray();
    }

    @Override
    public PdfDict newDict(String dictType) {
        return new PdfBoxDict(dictType);
    }

    @Override
    public PdfReader newReader(InputStream input) throws IOException {
        return new PdfBoxReader(input);
    }

    @Override
    public PdfStream newStream(byte[] bytes) throws IOException {
        return new PdfBoxStream(bytes);
    }

    @Override
    public PdfWriter newWriter(PdfReader reader, OutputStream output) throws IOException {
        return new PdfBoxWriter(((PdfBoxReader) reader).getPDDocument(), output);
    }

    @Override
    public PDFSignatureService newPAdESSignatureService() {
        return new PdfBoxSignatureService();
    }

    @Override
    public PDFTimestampService newTimestampSignatureService() {
        return new PdfBoxDocTimeStampService();
    }

}
