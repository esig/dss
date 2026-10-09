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
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.COSESign1;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelBDetachedByUriWithHttpParsTest extends AbstractCBAdESMultipleDocumentSignatureTest {

    private static final String DOC_ONE_NAME = "https://nowina.lu/pub/CBAdES/ObjectIdByURIHash-1.html";
    private static final String DOC_TWO_NAME = "https://nowina.lu/pub/CBAdES/ObjectIdByURIHash-2.html";

    private CBAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentToSigns;
    private CBAdESService service;

    @BeforeEach
    void init() throws Exception {
        DSSDocument documentOne = new FileDocument("src/test/resources/ObjectIdByURIHash-1.html");
        documentOne.setName(DOC_ONE_NAME);
        DSSDocument documentTwo = new FileDocument("src/test/resources/ObjectIdByURIHash-2.html");
        documentTwo.setName(DOC_TWO_NAME);
        documentToSigns = Arrays.asList(documentOne, documentTwo);

        service = new CBAdESService(getOfflineCertificateVerifier());

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI);
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return documentToSigns;
    }

    @Override
    protected void checkCOSESignStructure(COSESignStructure coseSignStructure) {
        super.checkCOSESignStructure(coseSignStructure);

        assertInstanceOf(COSESign1.class, coseSignStructure);
        COSESign1 coseSign = (COSESign1) coseSignStructure;

        assertRequirementsValid(coseSign.getProtectedHeader());
    }

    private void assertRequirementsValid(COSEProtectedHeader protectedHeader) {
        String cty = protectedHeader.getValue().getAsStringOrNull(COSEHeaderParameter.CONTENT_TYPE.cbor());
        assertNull(cty);

        CBORValue sigD = protectedHeader.getValue().getAsMapOrNull(COSEHeaderParameter.SIG_D.cbor());
        assertNotNull(sigD);

        CBORValue mId = sigD.get(COSEHeaderParameter.SIG_D_MID.cbor());
        assertNotNull(mId);
        assertTrue(mId.isTag());
        assertEquals(32, mId.getTag().longValue());
        assertNotNull(mId.getTaggedValue());
        assertEquals(SigDMechanism.OBJECT_ID_BY_URI.getCBAdESUri(), mId.getTaggedValue().asString());

        BigInteger hashM = sigD.getAsIntegerOrNull(COSEHeaderParameter.SIG_D_HASH_M.cbor());
        assertNull(hashM);

        CBORValue pars = sigD.getAsArrayOrNull(COSEHeaderParameter.SIG_D_PARS.cbor());
        assertNotNull(pars);
        assertEquals(2, pars.size());

        boolean firstDocFound = false;
        boolean secondDocFound = false;
        for (CBORValue nameValue : pars.getElements()) {
            assertTrue(nameValue.isTextString());
            String name = nameValue.asString();
            if (DOC_ONE_NAME.equals(name)) {
                firstDocFound = true;
            } else if (DOC_TWO_NAME.equals(name)) {
                secondDocFound = true;
            }
        }
        assertTrue(firstDocFound);
        assertTrue(secondDocFound);

        CBORValue hashV = sigD.getAsArrayOrNull(COSEHeaderParameter.SIG_D_HASH_V.cbor());
        assertNull(hashV);

        CBORValue ctys = sigD.getAsArrayOrNull(COSEHeaderParameter.SIG_D_CTYS.cbor());
        assertNotNull(ctys);
        assertEquals(2, ctys.size());
        for (CBORValue ctyValue : ctys.getElements()) {
            assertTrue(ctyValue.isTextString());
            String ctyStr = ctyValue.asString();
            assertEquals(MimeTypeEnum.HTML, MimeType.fromMimeTypeString(ctyStr));
        }
    }

    @Override
    protected void checkDigestMatchers(DiagnosticData diagnosticData) {
        super.checkDigestMatchers(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        boolean firstDocFound = false;
        boolean secondDocFound = false;
        List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
        assertEquals(2, signatureScopes.size());
        for (XmlSignatureScope signatureScope : signatureScopes) {
            if (DOC_ONE_NAME.equals(signatureScope.getName())) {
                firstDocFound = true;
            } else if (DOC_TWO_NAME.equals(signatureScope.getName())) {
                secondDocFound = true;
            }
        }
        assertTrue(firstDocFound);
        assertTrue(secondDocFound);
    }

    @Override
    protected MultipleDocumentsSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentToSigns;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}