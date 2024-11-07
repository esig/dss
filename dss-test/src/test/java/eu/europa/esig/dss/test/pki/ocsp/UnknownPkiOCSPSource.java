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
package eu.europa.esig.dss.test.pki.ocsp;

import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIOCSPSource;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.UnknownStatus;

public class UnknownPkiOCSPSource extends PKIOCSPSource {

    private static final long serialVersionUID = -2941608469469755568L;

    public UnknownPkiOCSPSource(CertEntityRepository<? extends CertEntity> certEntityRepository) {
        super(certEntityRepository);
    }

    @Override
    protected void addRevocationStatusToOCSPResponse(BasicOCSPRespBuilder builder, OCSPReq ocspReq, CertEntityRevocation certEntityRevocation) {
        Req r = ocspReq.getRequestList()[0];
        builder.addResponse(r.getCertID(), new UnknownStatus());
    }

}
