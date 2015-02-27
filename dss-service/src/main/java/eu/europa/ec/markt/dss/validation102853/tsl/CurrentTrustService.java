/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.tsl;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionsListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.InternationalNamesType;
import eu.europa.ec.markt.tsl.jaxb.tsl.MultiLangNormStringType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPServiceInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPServiceType;

/**
 * Current entry of the Service for the TrustedList
 *
 * @version $Revision: 1154 $ - $Date: 2012-02-23 16:04:49 +0100 (Thu, 23 Feb 2012) $
 */

class CurrentTrustService extends AbstractTrustService {

    private TSPServiceType service;

    /**
     * The default constructor for TrustService.
     *
     * @param service
     */
    CurrentTrustService(TSPServiceType service) {

        this.service = service;
    }

    @Override
    List<ExtensionType> getExtensions() {

        final TSPServiceInformationType serviceInfo = service.getServiceInformation();
        if (serviceInfo != null) {

            final ExtensionsListType extensionsList = serviceInfo.getServiceInformationExtensions();
            if (extensionsList != null) {
                return extensionsList.getExtension();
            }
        }
        return Collections.emptyList();
    }

    @Override
    DigitalIdentityListType getServiceDigitalIdentity() {

        return service.getServiceInformation().getServiceDigitalIdentity();
    }

    @Override
    String getStatus() {

        return service.getServiceInformation().getServiceStatus();
    }

    @Override
    Date getStatusStartDate() {

        if (service.getServiceInformation() != null && service.getServiceInformation().getStatusStartingTime() != null) {
            return service.getServiceInformation().getStatusStartingTime().toGregorianCalendar().getTime();
        } else {
            return null;
        }
    }

    @Override
    Date getStatusEndDate() {

        return null;
    }

    @Override
    String getType() {

        return service.getServiceInformation().getServiceTypeIdentifier();
    }

    @Override
    String getServiceName() {

		/* Return the english name or the first name */
        InternationalNamesType names = service.getServiceInformation().getServiceName();
        for (MultiLangNormStringType s : names.getName()) {
            if ("en".equalsIgnoreCase(s.getLang())) {
                return s.getValue();
            }
        }
        return names.getName().get(0).getValue();
    }
}
