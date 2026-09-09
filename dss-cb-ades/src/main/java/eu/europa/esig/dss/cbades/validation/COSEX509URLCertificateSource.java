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
package eu.europa.esig.dss.cbades.validation;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.CommonX509URLCertificateSource;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * This class provides utilities for certificates extraction referenced within a 'x5u' signed header parameter,
 * as specified in RFC 9360 "2. X.509 COSE Header Parameters".
 * <p>
 * In addition to the common implementation allowing extraction of DER or PEM encoded certificates or certificate chains,
 * this class also processing of COSE specific structures such as COSE_X509.
 *
 */
public class COSEX509URLCertificateSource extends CommonX509URLCertificateSource {

    private static final long serialVersionUID = -5032185260216133084L;

    /**
     * Constructor to create an instance of the class with a {@code dataLoader} to access
     * the certificates from the corresponding 'x5u' location in the runtime
     *
     * @param dataLoader {@link DataLoader}
     */
    public COSEX509URLCertificateSource(DataLoader dataLoader) {
        super(dataLoader);
    }

    @Override
    protected Collection<CertificateToken> loadCertificates(byte[] content) {
        if (CBORUtils.isCbor(content)) {
            try {
                // COSE_X509 = bstr / [ 2*certs: bstr ]
                CBORValue cborValue = CBORUtils.parseCbor(content);
                if (cborValue.isByteString()) {
                    return Collections.singletonList(DSSUtils.loadCertificate(cborValue.asBytes()));
                } else if (cborValue.isArray()) {
                    final List<CertificateToken> result = new ArrayList<>();
                    for (CBORValue cborItem : cborValue.getElements()) {
                        if (cborItem.isByteString()) {
                            result.add(DSSUtils.loadCertificate(cborItem.asBytes()));
                        } else {
                            throw new DSSException("Item of a CBOR Array shall be a CBOR Byte String!");
                        }
                    }
                    return result;

                } else {
                    throw new DSSException("CBOR content shall be represented either by a CBOR Byte String or CBOR Array!");
                }

            } catch (Exception e) {
                throw new DSSException(String.format("Unable to read the CBOR content : %s", e.getMessage()), e);
            }
        }

        return super.loadCertificates(content);
    }

}
