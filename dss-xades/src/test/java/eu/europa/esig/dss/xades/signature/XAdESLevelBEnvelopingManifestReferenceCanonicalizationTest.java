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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.DSSObject;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
class XAdESLevelBEnvelopingManifestReferenceCanonicalizationTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private static Stream<Arguments> data() {
        Object[] canonicalizations = { Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
                Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS };
        return combine(canonicalizations);
    }

    static Stream<Arguments> combine(Object[] canonicalizations) {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < canonicalizations.length; i++) {
            args.add(Arguments.of(canonicalizations[i]));
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Canonicalization {index} : {0}")
    @MethodSource("data")
    void test(String canonicalization) {
        documentToSign = new FileDocument("src/test/resources/manifest-joue.xml");

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        DSSReference manifestReference = new DSSReference();
        manifestReference.setContents(documentToSign);
        manifestReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
        manifestReference.setType("http://www.w3.org/2000/09/xmldsig#Manifest");
        manifestReference.setId("r-manifest");
        manifestReference.setUri("#manifest");
        manifestReference.setTransforms(Collections.singletonList(new CanonicalizationTransform(canonicalization)));

        DSSObject manifestObject = new DSSObject();
        manifestObject.setContent(documentToSign);
        manifestObject.setMimeType("http://www.w3.org/2000/09/xmldsig#Manifest");
        manifestReference.setObject(manifestObject);

        signatureParameters.setReferences(Collections.singletonList(manifestReference));

        service = new XAdESService(getOfflineCertificateVerifier());

        super.signAndVerify();
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        String xmlContent = new String(byteArray);
        assertTrue(xmlContent.contains("<ds:Object MimeType=\"http://www.w3.org/2000/09/xmldsig#Manifest\">"));
        assertTrue(xmlContent.contains("<ds:Manifest Id=\"manifest\">"));
    }

    @Override
    public void signAndVerify() {
        // skip
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(documentToSign);
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
