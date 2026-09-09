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
package eu.europa.esig.dss.cbades.signature;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.validation.AbstractCBAdESTestValidation;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESTripleLTATest extends AbstractCBAdESTestValidation {

    @Test
    void test() throws Exception {
        DSSDocument documentToSign = new InMemoryDocument("Hello world!".getBytes(), "HelloWorld");

        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_LT);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);

        CBAdESService service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        service.setTspSource(getGoodTsa());
        CBAdESSignatureParameters extendParameters = new CBAdESSignatureParameters();
        extendParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_LTA);
        DSSDocument extendedDocument = service.extendDocument(signedDocument, extendParameters);

        service.setTspSource(getGoodTsaCrossCertification());
        DSSDocument doubleLTADoc = service.extendDocument(extendedDocument, extendParameters);

        service.setTspSource(getSelfSignedTsa());
        DSSDocument tripleLTADoc = service.extendDocument(doubleLTADoc, extendParameters);
        checkSignedDocument(tripleLTADoc);

        Reports reports = verify(tripleLTADoc);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(4, timestampIds.size());

    }

    private void checkSignedDocument(DSSDocument document) {
        assertTrue(CBORUtils.isCbor(document));

        byte[] binaries = DSSUtils.toByteArray(document);
        CBORValue coseSign1 = CBORUtils.parseCbor(binaries);
        assertNotNull(coseSign1);
        assertTrue(coseSign1.isTag());

        coseSign1 = coseSign1.getTaggedValue();
        assertNotNull(coseSign1);
        assertTrue(coseSign1.isArray());

        assertEquals(4, coseSign1.size());

        CBORValue protectedHeader = coseSign1.get(0);
        assertTrue(protectedHeader.isByteString());

        CBORValue parsedProtectedHeader = CBORUtils.parseCbor(protectedHeader.asBytes());
        assertNotNull(parsedProtectedHeader);
        assertTrue(parsedProtectedHeader.isMap());
        assertTrue(parsedProtectedHeader.size() > 0);

        CBORValue unprotectedHeader = coseSign1.get(1);
        assertTrue(unprotectedHeader.isMap());

        assertEquals(1, unprotectedHeader.size());

        CBORValue uHeaders = unprotectedHeader.get(COSEHeaderParameter.U_HEADERS.cbor());
        assertNotNull(uHeaders);
        assertTrue(uHeaders.isArray());

        assertTrue(uHeaders.size() > 0);

        int sigTstCounter = 0;
        int valDataCounter = 0;
        int arcTstCounter = 0;

        for (CBORValue uHeadersComponent : uHeaders.getElements()) {
            assertTrue(uHeadersComponent.isByteString()); // cbor btsr encoded

            CBORValue uHeaderObject = CBORUtils.parseCbor(uHeadersComponent.asBytes());
            assertNotNull(uHeaderObject);
            assertTrue(uHeaderObject.isMap());

            assertEquals(1, uHeaderObject.size());

            CBORValue sigTst = uHeaderObject.get(COSEHeaderParameter.SIG_TST.cbor());
            if (sigTst != null) {
                ++sigTstCounter;

                CBORValue tstTokens = sigTst.getAsArrayOrNull(COSEHeaderParameter.TST_CONTAINER_TST_TOKENS.cbor());
                assertNotNull(tstTokens);
                assertEquals(1, tstTokens.size());
            }
            CBORValue valData = uHeaderObject.get(COSEHeaderParameter.VAL_DATA.cbor());
            if (valData != null) {
                ++valDataCounter;
            }
            CBORValue arcTst = uHeaderObject.get(COSEHeaderParameter.ARC_TST.cbor());
            if (arcTst != null) {
                ++arcTstCounter;

                CBORValue tstTokens = arcTst.getAsArrayOrNull(COSEHeaderParameter.TST_CONTAINER_TST_TOKENS.cbor());
                assertNotNull(tstTokens);
                assertEquals(1, tstTokens.size());
            }
        }

        assertEquals(1, sigTstCounter);
        assertEquals(3, valDataCounter);
        assertEquals(3, arcTstCounter);

        CBORValue payload = coseSign1.get(2);
        assertTrue(payload.isByteString());

        CBORValue signature = coseSign1.get(3);
        assertTrue(signature.isByteString());
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_TIMESTAMPS_ONLY);
        return validator;
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        assertEquals(4, diagnosticData.getTimestampList().size());

        int sigTstCounter = 0;
        int arcTstCounter = 0;
        int coveredCerts = 0;
        int coveredRevocation = 0;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                ++sigTstCounter;

            } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                ++arcTstCounter;
                assertTrue(timestampWrapper.getTimestampedCertificates().size() > coveredCerts);
                assertTrue(timestampWrapper.getTimestampedRevocations().size() > coveredRevocation);
                coveredCerts = timestampWrapper.getTimestampedCertificates().size();
                coveredRevocation = timestampWrapper.getTimestampedRevocations().size();
            }
        }
        assertEquals(1, sigTstCounter);
        assertEquals(3, arcTstCounter);
    }

    @Override
    protected String getSigningAlias() {
        return RSA_SHA3_USER;
    }

    @Override
    public void validate() {
        // do nothing
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return null;
    }

}
