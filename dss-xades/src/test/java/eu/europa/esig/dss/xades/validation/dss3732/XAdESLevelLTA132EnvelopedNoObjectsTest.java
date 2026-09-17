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
package eu.europa.esig.dss.xades.validation.dss3732;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

import java.io.File;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelLTA132EnvelopedNoObjectsTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument(new File("src/test/resources/validation/dss3732/xades-enveloped-arcTst132-no-objects.xml"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_A, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
        assertFalse(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        boolean crl5Found = false;
        boolean crl7Found = false;
        for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
            if (RevocationType.CRL == revocationWrapper.getRevocationType()) {
                BigInteger crlNumber = revocationWrapper.getCRLNumber();
                assertNotNull(crlNumber);
                if (5 == crlNumber.intValue()) {
                    crl5Found = true;
                } else if (7 == crlNumber.intValue()) {
                    crl7Found = true;
                }
            }
        }
        assertTrue(crl5Found);
        assertTrue(crl7Found);
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        int sigTstCounter = 0;
        int arcTstCounter = 0;
        for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
            if (TimestampType.SIGNATURE_TIMESTAMP == timestamp.getType()) {
                assertTrue(timestamp.isMessageImprintDataFound());
                assertTrue(timestamp.isMessageImprintDataIntact());
                assertTrue(timestamp.isSignatureIntact());
                assertTrue(timestamp.isSignatureValid());
                ++sigTstCounter;

            } else if (TimestampType.ARCHIVE_TIMESTAMP == timestamp.getType()) {
                assertTrue(timestamp.isMessageImprintDataFound());
                assertFalse(timestamp.isMessageImprintDataIntact());
                assertTrue(timestamp.isSignatureIntact());
                assertFalse(timestamp.isSignatureValid());
                ++arcTstCounter;
            }
        }
        assertEquals(1, sigTstCounter);
        assertEquals(1, arcTstCounter);
    }

}
