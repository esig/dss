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
package eu.europa.esig.dss.attestation.sd.jwt.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlAttestation;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

class SDJWTJsonSerializationAttestationBrokenSignatureTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(this.getClass().getResourceAsStream("/validation/sdjwt-json-broken-signature.json"));
    }

    @Override
    protected void checkBLevelValid(final DiagnosticData diagnosticData) {
        assertEquals(1, diagnosticData.getSignatures().size());
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertFalse(signatureWrapper.isSignatureIntact());
            assertFalse(signatureWrapper.isSignatureValid());
            assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
        }
    }

    @Override
    protected void verifySimpleReport(final SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        XmlAttestation attestation = simpleReport.getAttestationById(simpleReport.getFirstAttestationId());
        assertEquals(Indication.FAILED, attestation.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, attestation.getSubIndication());

        assertTrue(attestation.getAttestationSignature().get(0).getAdESValidationDetails().getError().stream().anyMatch(m -> MessageTag.BBB_CV_IRDOI_ANS.getId().equals(m.getKey())));
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        // skip
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
