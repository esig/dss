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

import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.COSESign;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelBDetachedTest extends AbstractCBAdESTestSignature {

    private DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> service;
    private DSSDocument documentToSign;
    private Date signingDate;

    @BeforeEach
    void init() throws Exception {
        service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        documentToSign = new InMemoryDocument("Hello World!".getBytes(), "doc.txt");
        signingDate = new Date();
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        return signatureParameters;
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(documentToSign);
    }

    @Override
    protected void checkCOSESignStructure(COSESignStructure coseSignStructure) {
        super.checkCOSESignStructure(coseSignStructure);

        assertInstanceOf(COSESign.class, coseSignStructure);
        COSESign coseSign = (COSESign) coseSignStructure;
        assertEquals(1, coseSign.getSignatures().size());

        assertRequirementsValid(coseSign.getSignatures().get(0).getProtectedHeader());
    }

    private void assertRequirementsValid(COSEProtectedHeader protectedHeader) {
        String cty = protectedHeader.getAsString(COSEHeaderParameter.CONTENT_TYPE.cbor());
        assertNull(cty);

        CBORMap sigD = protectedHeader.getAsMap(COSEHeaderParameter.SIG_D.cbor());
        assertNotNull(sigD);

        CBORObject mId = sigD.getHeader(COSEHeaderParameter.SIG_D_MID.cbor());
        assertNotNull(mId);
        assertTrue(mId.isTagged());
        assertEquals(32, mId.getTag().getValue());
        assertEquals(SigDMechanism.OBJECT_ID_BY_URI_HASH.getCBAdESUri(), mId.getValueAsString());

        Long hashM = sigD.getAsLong(COSEHeaderParameter.SIG_D_HASH_M.cbor());
        assertNotNull(hashM);
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.forCOSE(hashM);
        assertNotNull(digestAlgorithm);

        CBORArray pars = sigD.getAsArray(COSEHeaderParameter.SIG_D_PARS.cbor());
        assertNotNull(pars);
        assertFalse(pars.isEmpty());
        assertEquals(1, pars.getSize());
        assertEquals(documentToSign.getName(), pars.getAsString(0));

        CBORArray hashV = sigD.getAsArray(COSEHeaderParameter.SIG_D_HASH_V.cbor());
        assertNotNull(hashV);
        assertFalse(hashV.isEmpty());
        assertEquals(1, hashV.getSize());
        assertArrayEquals(documentToSign.getDigestValue(digestAlgorithm), hashV.getAsBinaries(0));

        CBORArray ctys = sigD.getAsArray(COSEHeaderParameter.SIG_D_CTYS.cbor());
        assertNotNull(ctys);
        assertFalse(ctys.isEmpty());
        assertEquals(1, ctys.getSize());
        assertEquals(documentToSign.getMimeType().getMimeTypeString(), ctys.getAsString(0));
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        super.checkSignatureScopes(diagnosticData);

        assertEquals(1, diagnosticData.getOriginalSignerDocuments().size());

        SignerDataWrapper signerData = diagnosticData.getOriginalSignerDocuments().get(0);
        XmlDigestAlgoAndValue digestAlgoAndValue = signerData.getDigestAlgoAndValue();
        assertNotNull(digestAlgoAndValue);

        assertArrayEquals(documentToSign.getDigestValue(digestAlgoAndValue.getDigestMethod()), digestAlgoAndValue.getDigestValue());
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
