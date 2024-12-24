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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.cookbook.example.CustomMimeTypeLoader;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MimeTypeTest {

    @Test
    void test() {
        assertEquals(CustomMimeTypeLoader.CustomMimeType.CSS, MimeType.fromFileName("style.css"));
        assertEquals(CustomMimeTypeLoader.CustomMimeType.WEBM, MimeType.fromFileName("audio.webm"));
        assertEquals(CustomMimeTypeLoader.CustomMimeType.JPEG, MimeType.fromFileName("image.jpeg"));

        assertEquals(CustomMimeTypeLoader.CustomMimeType.CSS, MimeType.fromMimeTypeString("text/css"));
        assertEquals(CustomMimeTypeLoader.CustomMimeType.WEBM, MimeType.fromMimeTypeString("audio/webm"));
        assertEquals(CustomMimeTypeLoader.CustomMimeType.JPEG, MimeType.fromMimeTypeString("image/jpeg"));
    }

    @Test
    void defaultMimeTypeEnumTest() {
        assertEquals(MimeTypeEnum.TEXT, MimeType.fromFileName("text.txt"));
        assertEquals(MimeTypeEnum.TEXT, MimeType.fromMimeTypeString("text/plain"));
    }

    @Test
    void notDefinedTest() {
        assertEquals(MimeTypeEnum.BINARY, MimeType.fromFileName("text.text"));
        assertEquals(MimeTypeEnum.BINARY, MimeType.fromMimeTypeString("text/new"));
    }

    @Test
    void overwriteMimeTypeTest() {
        assertEquals(CustomMimeTypeLoader.CustomMimeType.CER, MimeType.fromFile(new File("D-TRUST_CA_3-1_2016.cer")));
        assertEquals(CustomMimeTypeLoader.CustomMimeType.CER, MimeType.fromFile(new File("src/test/resources/AdobeCA.p7c")));
    }

}
