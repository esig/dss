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
package eu.europa.esig.dss.eaa.mdoc.creation;

import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationRevocationWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.eaa.mdoc.MdocConstants;
import eu.europa.esig.dss.eaa.mdoc.pki.PKICWTStatusListSource;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.spi.eaa.status.AttestationRevocationSource;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MdocISONonMdLWithStatusListTest extends AbstractMdocPresentationTestIssuance {

    private MdocPayloadParameters payloadParameters;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new MdocPayloadParameters();
        payloadParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);
        payloadParameters.setDeviceKey(getSigningCert());

        payloadParameters.setStatusList(0, "https://dss.nowina.lu/pki-factory/eaa/status_list");

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
    }

    @Override
    protected AttestationRevocationSource getEAAStatusSource() {
        return new PKICWTStatusListSource(getCertEntityRepository(), getCertEntity(GOOD_CA));
    }

    @Override
    protected void checkEAARevocations(DiagnosticData diagnosticData) {
        super.checkEAARevocations(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        List<AttestationRevocationWrapper> eaaStatuses = eaa.getAttestationRevocations();
        assertEquals(1, eaaStatuses.size());
        assertEquals(AttestationStatus.VALID, eaaStatuses.get(0).getStatus());
        assertEquals("application/statuslist+cwt", eaaStatuses.get(0).getType());
    }

    @Override
    protected MdocPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected CBAdESSignatureParameters getKeyBindingSignatureParameters() {
        return null;
    }

    @Override
    protected MdocKeyBindingParameters getKeyBindingParameters() {
        return null;
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
