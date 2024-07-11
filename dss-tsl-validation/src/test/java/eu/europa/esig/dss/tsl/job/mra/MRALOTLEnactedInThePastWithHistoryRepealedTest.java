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
package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.MRAStatus;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MRALOTLEnactedInThePastWithHistoryRepealedTest extends MRALOTLTest {

    private Date startingDate;

    @BeforeEach
    void initTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.YEAR, -2);
        this.startingDate = calendar.getTime();
    }

    @Override
    protected DSSDocument getOriginalLOTL() {
        return new FileDocument("src/test/resources/mra-zz-lotl-history.xml");
    }

    @Override
    protected Date getTrustServiceEquivalenceStatusStartingTime() {
        return startingDate;
    }

    @Override
    protected String getTrustServiceEquivalenceStatus() {
        return MRAStatus.ENACTED.getUri();
    }

    @Override
    protected String getTrustServiceEquivalenceHistoryStatus() {
        return MRAStatus.REPEALED.getUri();
    }

    @Override
    protected SignatureQualification getFinalSignatureQualification() {
        return SignatureQualification.QESIG;
    }

    @Override
    protected void verifySigningCertificate(DiagnosticData diagnosticData) {
        super.verifySigningCertificate(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<TrustServiceWrapper> trustServices = signingCertificate.getTrustServices();
        assertEquals(1, trustServices.size());

        int enactedCounter = 0;
        int repealedCounter = 0;
        for (TrustServiceWrapper trustService : trustServices) {
            if (trustService.isEnactedMRA()) {
                ++enactedCounter;
            } else {
                ++repealedCounter;
            }
        }
        assertEquals(1, enactedCounter);
        assertEquals(0, repealedCounter);
    }

}
