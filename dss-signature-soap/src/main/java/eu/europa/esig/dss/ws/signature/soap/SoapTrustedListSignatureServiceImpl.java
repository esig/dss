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
package eu.europa.esig.dss.ws.signature.soap;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteTrustedListSignatureService;
import eu.europa.esig.dss.ws.signature.dto.DataToSignTrustedListDTO;
import eu.europa.esig.dss.ws.signature.dto.SignTrustedListDTO;
import eu.europa.esig.dss.ws.signature.soap.client.SoapTrustedListSignatureService;

/**
 * SOAP implementation for XML Trusted List signing service
 *
 */
public class SoapTrustedListSignatureServiceImpl implements SoapTrustedListSignatureService {

    private static final long serialVersionUID = -2982455071210880177L;

    /** The service to use */
    private RemoteTrustedListSignatureService service;

    /**
     * Default construction instantiating object with null RemoteTrustedListSignatureService
     */
    public SoapTrustedListSignatureServiceImpl() {
        // empty
    }

    /**
     * Sets the remote XML Trusted List signing service
     *
     * @param service {@link RemoteTrustedListSignatureService}
     */
    public void setService(RemoteTrustedListSignatureService service) {
        this.service = service;
    }

    @Override
    public ToBeSignedDTO getDataToSign(DataToSignTrustedListDTO dataToSign) {
        return service.getDataToSign(dataToSign.getTrustedList(), dataToSign.getParameters());
    }

    @Override
    public RemoteDocument signDocument(SignTrustedListDTO signTrustedList) {
        return service.signDocument(signTrustedList.getTrustedList(), signTrustedList.getParameters(),
                signTrustedList.getSignatureValue());
    }

}
