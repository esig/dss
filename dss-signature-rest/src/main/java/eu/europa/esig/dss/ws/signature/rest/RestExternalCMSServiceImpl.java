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
package eu.europa.esig.dss.ws.signature.rest;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.common.RemoteExternalCMSService;
import eu.europa.esig.dss.ws.signature.dto.DataToSignExternalCmsDTO;
import eu.europa.esig.dss.ws.signature.dto.SignMessageDigestExternalCmsDTO;
import eu.europa.esig.dss.ws.signature.rest.client.RestExternalCMSService;

/**
 * REST implementation of the remote CMS signature generation suitable for PAdES signature creation
 *
 */
public class RestExternalCMSServiceImpl implements RestExternalCMSService {

    private static final long serialVersionUID = 6958836951128294905L;

    /** The service to use */
    private RemoteExternalCMSService service;

    /**
     * Default construction instantiating object with null RestExternalCMSServiceImpl
     */
    public RestExternalCMSServiceImpl() {
        // empty
    }

    /**
     * Sets the remote service for external CMS creation suitable for PAdES signing
     *
     * @param service {@link RemoteExternalCMSService}
     */
    public void setService(RemoteExternalCMSService service) {
        this.service = service;
    }

    @Override
    public ToBeSignedDTO getDataToSign(DataToSignExternalCmsDTO dataToSign) {
        return service.getDataToSign(dataToSign.getMessageDigest(), dataToSign.getParameters());
    }

    @Override
    public RemoteDocument signMessageDigest(SignMessageDigestExternalCmsDTO signMessageDigest) {
        return service.signMessageDigest(signMessageDigest.getMessageDigest(), signMessageDigest.getParameters(),
                signMessageDigest.getSignatureValue());
    }

}
