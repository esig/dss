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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;

class JAdESLevelBWithSigTAfterObsolescenceSerializationTest extends JAdESLevelBWithSigTSerializationTest {

    private Date signingTime;

    @BeforeEach
    void initTime() {
        signingTime = DSSUtils.getUtcDate(2025, Calendar.JULY, 15);
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingTime);
        return signatureParameters;
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // iat header shall be present for JAdES-BASELINE-B signature produced starting at 2025-07-15T00:00:00Z (cardinality == 1)!
        Assertions.assertEquals(SignatureLevel.JSON_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

}
