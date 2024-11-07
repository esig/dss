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
package eu.europa.esig.dss.asic.xades.signature.asics;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ASiCSXAdESLevelLTADoubleSignatureTest extends AbstractASiCSXAdESTestSignature {

    private final DSSDocument ORIGINAL_DOC = new InMemoryDocument("Hello World !".getBytes(), "test.txt", MimeTypeEnum.TEXT);

    private DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> service;
    private ASiCWithXAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private String signingAlias;

    @BeforeEach
    void init() throws Exception {
        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = ORIGINAL_DOC;
        signingAlias = GOOD_USER;

        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());

        DSSDocument firstSignedDocument = super.sign();
        assertNotNull(firstSignedDocument);

        documentToSign = firstSignedDocument;
        signingAlias = RSA_SHA3_USER;

        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());

        DSSDocument secondSignedDocument = super.sign();
        assertNotNull(secondSignedDocument);

        documentToSign = ORIGINAL_DOC;

        return secondSignedDocument;
    }

    @Override
    protected void checkExtractedContent(ASiCContent asicContent) {
        super.checkExtractedContent(asicContent);

        int foundSignatures = 0;
        List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
        for (DSSDocument signatureDocument : signatureDocuments) {
            Document document = DomUtils.buildDOM(signatureDocument);

            NodeList childNodes = document.getDocumentElement().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node node = childNodes.item(i);
                if (node instanceof Element) {
                    Element element = (Element) node;
                    assertEquals("Signature", element.getLocalName());

                    NodeList mimeTypeList = DomUtils.getNodeList(element, new XAdES132Path().getDataObjectFormatMimeType());
                    assertEquals(1, mimeTypeList.getLength());
                    assertEquals(MimeTypeEnum.TEXT.getMimeTypeString(), mimeTypeList.item(0).getTextContent());

                    ++foundSignatures;
                }
            }
        }
        assertEquals(2, foundSignatures);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkCertificateChain(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signatureOne = diagnosticData.getSignatures().get(0);
        SignatureWrapper signatureTwo = diagnosticData.getSignatures().get(1);
        assertFalse(Arrays.equals(signatureOne.getSignatureDigestReference().getDigestValue(),
                signatureTwo.getSignatureDigestReference().getDigestValue()));
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        for (String signatureId : simpleReport.getSignatureIdList()) {
            assertEquals(signatureParameters.getSignatureLevel(), simpleReport.getSignatureFormat(signatureId));
            assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(signatureId));
        }
    }

    @Override
    protected DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
