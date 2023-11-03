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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterEnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.reference.XPathEnvelopedSignatureTransform;
import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

// See DSS-3105
@Tag("slow")
public class XAdESLevelBEnvelopedSignDocWithCommentsTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private static Stream<Arguments> data() {
        String[] refUris = { "", "#xpointer(/)" };
        DSSTransform[] envelopedSigTransforms = { new EnvelopedSignatureTransform(),
                new XPathEnvelopedSignatureTransform(), new XPath2FilterEnvelopedSignatureTransform() };
        String[] canonicalizations = { Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
                Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS };
        return random(refUris, envelopedSigTransforms, canonicalizations);
    }

    static Stream<Arguments> random(String[] refUris, DSSTransform[] envelopedSigTransforms, String[] canonicalizations) {
        List<Arguments> args = new ArrayList<>();
        for (String refUri : refUris) {
            for (DSSTransform transform : envelopedSigTransforms) {
                for (String canonicalization : canonicalizations) {
                    args.add(Arguments.of(refUri, transform, canonicalization));
                }
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Sign Enveloped XAdES {index} : {0} - {1} - {2}")
    @MethodSource("data")
    public void test(String refUri, DSSTransform envelopedSigTransform, String canonicalization) {
        documentToSign = new FileDocument(new File("src/test/resources/sample-with-comments.xml"));
        service = new XAdESService(getOfflineCertificateVerifier());

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        final List<DSSReference> references = new ArrayList<>();

        DSSReference dssReference = new DSSReference();
        dssReference.setId("r-" + documentToSign.getName());
        dssReference.setUri(refUri);
        dssReference.setContents(documentToSign);
        dssReference.setDigestMethodAlgorithm(signatureParameters.getDigestAlgorithm());

        final List<DSSTransform> transforms = new ArrayList<>();

        transforms.add(envelopedSigTransform);

        CanonicalizationTransform dssTransform = new CanonicalizationTransform(canonicalization);
        transforms.add(dssTransform);

        dssReference.setTransforms(transforms);
        references.add(dssReference);

        signatureParameters.setReferences(references);
        super.signAndVerify();
    }

    @Override
    public void signAndVerify() {
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
