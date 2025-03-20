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
package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.awt.Color;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

/**
 * For manual testing
 *
 */
@Tag("slow")
class PAdESVisibleSignRotatedDocumentTest extends AbstractPAdESTestSignature {

    protected PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    private static Stream<Arguments> data() {
        List<DSSDocument> signable = new ArrayList<>();
        signable.add(new InMemoryDocument(PAdESVisibleSignRotatedDocumentTest.class.getResourceAsStream("/visualSignature/test.pdf"), "test"));
        signable.add(new InMemoryDocument(PAdESVisibleSignRotatedDocumentTest.class.getResourceAsStream("/visualSignature/test_90.pdf"), "test_90"));
        signable.add(new InMemoryDocument(PAdESVisibleSignRotatedDocumentTest.class.getResourceAsStream("/visualSignature/test_180.pdf"), "test_180"));
        signable.add(new InMemoryDocument(PAdESVisibleSignRotatedDocumentTest.class.getResourceAsStream("/visualSignature/test_270.pdf"), "test_270"));
        signable.add(new InMemoryDocument(PAdESVisibleSignRotatedDocumentTest.class.getResourceAsStream("/visualSignature/test_-90.pdf"), "test_-90"));
        signable.add(new InMemoryDocument(PAdESVisibleSignRotatedDocumentTest.class.getResourceAsStream("/visualSignature/test_-180.pdf"), "test_-180"));
        signable.add(new InMemoryDocument(PAdESVisibleSignRotatedDocumentTest.class.getResourceAsStream("/visualSignature/test_-270.pdf"), "test_-270"));

        Collection<Arguments> dataToRun = new ArrayList<>();
        for (DSSDocument document : signable) {
            for (VisualSignatureRotation rotation : VisualSignatureRotation.values()) {
                dataToRun.add(Arguments.of(document, rotation));
            }
        }
        return dataToRun.stream();
    }

    @ParameterizedTest(name = "Text visual signature for document and rotation {index} : {0} : {1}")
    @MethodSource("data")
    void textTest(DSSDocument document, VisualSignatureRotation rotation) {
        this.documentToSign = document;
        String originalDocName = documentToSign.getName();

        this.documentToSign.setName("text_" + originalDocName + "_" + rotation.name() + ".pdf");

        SignatureImageParameters imageParameters = new SignatureImageParameters();

        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("My signature");
        textParameters.setBackgroundColor(Color.PINK);
        imageParameters.setTextParameters(textParameters);

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(50);
        fieldParameters.setHeight(50);
        fieldParameters.setWidth(100);
        fieldParameters.setRotation(rotation);
        imageParameters.setFieldParameters(fieldParameters);

        signatureParameters.setImageParameters(imageParameters);

        super.signAndVerify();

        this.documentToSign.setName(originalDocName);
    }

    @ParameterizedTest(name = "Image visual signature for document and rotation {index} : {0} : {1}")
    @MethodSource("data")
    void imageTest(DSSDocument document, VisualSignatureRotation rotation) {
        this.documentToSign = document;
        String originalDocName = documentToSign.getName();

        this.documentToSign.setName("image_" + originalDocName + "_" + rotation.name() + ".pdf");

        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setBackgroundColor(Color.PINK);
        imageParameters.setImage(new InMemoryDocument(PAdESVisibleSignRotatedDocumentTest.class.getResourceAsStream("/signature-image.png")));

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(50);
        fieldParameters.setHeight(50);
        fieldParameters.setWidth(100);
        fieldParameters.setRotation(rotation);
        imageParameters.setFieldParameters(fieldParameters);

        signatureParameters.setImageParameters(imageParameters);

        super.signAndVerify();

        this.documentToSign.setName(originalDocName);
    }

    @Override
    public void signAndVerify() {
        // do nothing
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
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
