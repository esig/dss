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
import eu.europa.esig.dss.ws.signature.common.RemoteListOfTrustedEntitiesSignatureService;
import eu.europa.esig.dss.ws.signature.dto.DataToSignListOfTrustedEntitiesDTO;
import eu.europa.esig.dss.ws.signature.dto.SignListOfTrustedEntitiesDTO;
import eu.europa.esig.dss.ws.signature.rest.client.RestListOfTrustedEntitiesSignatureService;

/**
 * REST implementation of the remote list of trusted entities signing service
 *
 */
public class RestListOfTrustedEntitiesSignatureServiceImpl implements RestListOfTrustedEntitiesSignatureService {

    private static final long serialVersionUID = 2929769970186252017L;

    /** The service to use */
    private RemoteListOfTrustedEntitiesSignatureService service;

    /**
     * Default construction instantiating object with null RemoteListOfTrustedEntitiesSignatureService
     */
    public RestListOfTrustedEntitiesSignatureServiceImpl() {
        // empty
    }

    /**
     * Sets the remote service for List of Trusted Entities signing
     *
     * @param service {@link RemoteListOfTrustedEntitiesSignatureService}
     */
    public void setService(RemoteListOfTrustedEntitiesSignatureService service) {
        this.service = service;
    }

    @Override
    public ToBeSignedDTO getDataToSign(DataToSignListOfTrustedEntitiesDTO dataToSign) {
        return service.getDataToSign(dataToSign.getListOfTrustedEntities(), dataToSign.getParameters());
    }

    @Override
    public RemoteDocument signDocument(SignListOfTrustedEntitiesDTO signListOfTrustedEntities) {
        return service.signDocument(signListOfTrustedEntities.getListOfTrustedEntities(), signListOfTrustedEntities.getParameters(),
                signListOfTrustedEntities.getSignatureValue());
    }

}
