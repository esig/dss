package eu.europa.esig.dss.xml.utils;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.InputStream;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XMLCanonicalizerTest {

    @Test
    public void canonicalizeInputStreamTest() throws Exception {
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
    public void canonicalizeNodeTest() throws Exception {
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
    public void canonicalizeBytesTest() throws Exception {
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
