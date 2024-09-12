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
package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.DefaultASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESASiCContentBuilder;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.Date;

class ASiCSCAdESCreateContainerFromDigestDocumentsTest extends AbstractASiCSCAdESTestSignature {

    private CAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private DSSDocument originalDocument;

    @BeforeEach
    void init() throws Exception {
        originalDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        service = new CAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        Digest digest = new Digest(signatureParameters.getDigestAlgorithm(), originalDocument.getDigestValue(signatureParameters.getDigestAlgorithm()));
        DigestDocument digestDocument = new DigestDocument(digest, originalDocument.getName());
        digestDocument.setMimeType(originalDocument.getMimeType());

        ToBeSigned dataToSign = service.getDataToSign(digestDocument, signatureParameters);
        byte[] dtbsr = DSSUtils.digest(signatureParameters.getDigestAlgorithm(), dataToSign.getBytes());
        byte[] rsaDtbsr = DSSUtils.encodeRSADigest(signatureParameters.getDigestAlgorithm(), dtbsr);

        SignatureValue signatureValue = getToken().signDigest(new Digest(signatureParameters.getDigestAlgorithm(), rsaDtbsr), signatureParameters.getSignatureAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(digestDocument, signatureParameters, signatureValue);

        ASiCContent asicContent = new ASiCWithCAdESASiCContentBuilder().build(
                Collections.singletonList(originalDocument), signatureParameters.aSiC().getContainerType());

        DefaultASiCWithCAdESFilenameFactory asicWithCAdESFilenameFactory = new DefaultASiCWithCAdESFilenameFactory();

        String signatureFilename = asicWithCAdESFilenameFactory.getSignatureFilename(asicContent);
        signedDocument.setName(signatureFilename);
        asicContent.setSignatureDocuments(Collections.singletonList(signedDocument));

        ASiCUtils.ensureMimeTypeAndZipComment(asicContent, signatureParameters.aSiC());
        MimeType mimeType = ASiCUtils.getMimeType(asicContent.getMimeTypeDocument());

        DSSDocument zipArchive = ZipUtils.getInstance().createZipArchive(asicContent);
        zipArchive.setName("asic." + mimeType.getExtension());
        zipArchive.setMimeType(mimeType);
        return zipArchive;
    }

    @Override
    protected ASiCWithCAdESService getService() {
        return new ASiCWithCAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return originalDocument;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
