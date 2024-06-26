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
package eu.europa.esig.dss.pades.signature.extension;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.openpdf.ITextDocumentReader;

import java.io.IOException;

public class ITextLevelBEdDSAPdf20DeveloperExtensionTest extends PAdESLevelBEdDSAPdf20DeveloperExtensionTest {

    @Override
    protected PdfDocumentReader getDocumentReader(DSSDocument document) throws IOException {
        return new ITextDocumentReader(document);
    }

}
