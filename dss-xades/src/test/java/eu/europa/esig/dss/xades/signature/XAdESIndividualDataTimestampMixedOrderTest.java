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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class XAdESIndividualDataTimestampMixedOrderTest extends AbstractXAdESMultipleDocumentsSignatureService {

    private static final String FILE1 = "src/test/resources/sample.xml";
    private static final String FILE2 = "src/test/resources/sampleISO.xml";

    private XAdESService service;
    private XAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentsToSign;

    @BeforeEach
    public void init() throws Exception {
        documentsToSign = new ArrayList<>();
        DSSDocument firstFile = new FileDocument(FILE1);
        documentsToSign.add(firstFile);

        DSSDocument secondFile = new FileDocument(FILE2);
        documentsToSign.add(secondFile);

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        byte[] firstDocBinaries = DSSUtils.toByteArray(firstFile);
        byte[] secondDocBinaries = DSSUtils.toByteArray(secondFile);

        byte[] concatenatedResult = Utils.concat(secondDocBinaries, firstDocBinaries);
        byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, concatenatedResult);
        TimestampBinary timeStampResponse = getAlternateGoodTsa().getTimeStampResponse(DigestAlgorithm.SHA256, digest);
        
        TimestampToken timestampToken = new TimestampToken(timeStampResponse.getBytes(), TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
        String deterministicId = signatureParameters.getDeterministicId();
        timestampToken.setTimestampIncludes(Arrays.asList(
                new TimestampInclude("r-" + deterministicId + "-2", true),
                new TimestampInclude("r-" + deterministicId + "-1", true) ));
        timestampToken.setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
        signatureParameters.setContentTimestamps(Arrays.asList(timestampToken));

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected XAdESService getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentsToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
