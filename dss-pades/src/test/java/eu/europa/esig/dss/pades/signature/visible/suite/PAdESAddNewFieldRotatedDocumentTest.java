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

import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * For manual testing
 *
 */
@Tag("slow")
public class PAdESAddNewFieldRotatedDocumentTest extends AbstractPAdESTestValidation {

    protected PAdESService service;
    private SignatureFieldParameters fieldParameters;

    private DSSDocument docWithEmptyField;

    @BeforeEach
    void init() throws Exception {
        fieldParameters = new SignatureFieldParameters();
        fieldParameters.setFieldId("signature1");
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(50);
        fieldParameters.setHeight(50);
        fieldParameters.setWidth(100);

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
    void test(DSSDocument document, VisualSignatureRotation rotation) throws IOException {
        this.fieldParameters.setRotation(rotation);

        this.docWithEmptyField = service.addNewSignatureField(document, fieldParameters);
        //docWithEmptyField.save("target/" +  document.getName() + "_" + rotation.name() + ".pdf");

        List<String> availableSignatureFields = service.getAvailableSignatureFields(docWithEmptyField);
        assertEquals(1, availableSignatureFields.size());
        assertEquals(fieldParameters.getFieldId(), availableSignatureFields.get(0));
    }

    @Override
    public void validate() {
        // skip
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return null;
    }

}
