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
package eu.europa.esig.dss.test.pki.crl;

import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;

import java.util.Date;
import java.util.Map;

public class UnknownPkiCRLSource extends PKICRLSource {

    private static final long serialVersionUID = 6793262225588156549L;

    public UnknownPkiCRLSource(CertEntityRepository<? extends CertEntity> certEntityRepository) {
        super(certEntityRepository);
        super.setNextUpdate(new Date());
    }

    protected void addRevocationsToCRL(X509v2CRLBuilder builder, Map<CertEntity, CertEntityRevocation> revocationList) {
        revocationList.forEach((key, value) -> {
            X509CertificateHolder entry = DSSASN1Utils.getX509CertificateHolder(key.getCertificateToken());
            builder.addCRLEntry(entry.getSerialNumber(), value.getRevocationDate(), CRLReason.unspecified);
        });
    }

}
