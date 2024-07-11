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
package eu.europa.esig.dss.xml.utils;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.InputStream;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertEquals;

class XMLCanonicalizerTest {

    @Test
    void canonicalizeInputStreamTest() throws Exception {
        DSSDocument document = new FileDocument("src/test/resources/sample-c14n.xml");
        try (InputStream is = document.openStream()) {
            byte[] canonicalized = XMLCanonicalizer
                    .createInstance(CanonicalizationMethod.INCLUSIVE)
                    .canonicalize(is);
            MessageDigest messageDigest = DigestAlgorithm.SHA256.getMessageDigest();
            assertEquals("/TiBXkCOtm0bSdOukpXHtqSu6G5EPRfwyYH9DJ9YtCE=",
                    Utils.toBase64(messageDigest.digest(canonicalized)));
        }
        try (InputStream is = document.openStream()) {
            byte[] canonicalized = XMLCanonicalizer
                    .createInstance(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS)
                    .canonicalize(is);
            MessageDigest messageDigest = DigestAlgorithm.SHA256.getMessageDigest();
            assertEquals("0VrRKOvUCLDg3QSMAzIrdahAmiCo/AFTFAjd5FZDx+0=",
                    Utils.toBase64(messageDigest.digest(canonicalized)));
        }
    }

    @Test
    void canonicalizeNodeTest() throws Exception {
        DSSDocument document = new FileDocument("src/test/resources/sample-c14n.xml");
        Document dom = DomUtils.buildDOM(document);

        byte[] canonicalized = XMLCanonicalizer
                .createInstance(CanonicalizationMethod.INCLUSIVE)
                .canonicalize(dom);
        MessageDigest messageDigest = DigestAlgorithm.SHA256.getMessageDigest();
        assertEquals("/TiBXkCOtm0bSdOukpXHtqSu6G5EPRfwyYH9DJ9YtCE=",
                Utils.toBase64(messageDigest.digest(canonicalized)));
        canonicalized = XMLCanonicalizer
                .createInstance(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS)
                .canonicalize(dom);
        messageDigest = DigestAlgorithm.SHA256.getMessageDigest();
        assertEquals("0VrRKOvUCLDg3QSMAzIrdahAmiCo/AFTFAjd5FZDx+0=",
                Utils.toBase64(messageDigest.digest(canonicalized)));
    }

    @Test
    void canonicalizeBytesTest() throws Exception {
        DSSDocument document = new FileDocument("src/test/resources/sample-c14n.xml");

        byte[] byteArray;
        try (InputStream is = document.openStream()) {
            byteArray = Utils.toByteArray(is);
        }

        byte[] canonicalized = XMLCanonicalizer
                .createInstance(CanonicalizationMethod.INCLUSIVE)
                .canonicalize(byteArray);
        MessageDigest messageDigest = DigestAlgorithm.SHA256.getMessageDigest();
        assertEquals("/TiBXkCOtm0bSdOukpXHtqSu6G5EPRfwyYH9DJ9YtCE=",
                Utils.toBase64(messageDigest.digest(canonicalized)));
        canonicalized = XMLCanonicalizer
                .createInstance(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS)
                .canonicalize(byteArray);
        messageDigest = DigestAlgorithm.SHA256.getMessageDigest();
        assertEquals("0VrRKOvUCLDg3QSMAzIrdahAmiCo/AFTFAjd5FZDx+0=",
                Utils.toBase64(messageDigest.digest(canonicalized)));
    }

}
