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
import eu.europa.ec.markt.tsl.jaxb.tsl.InternationalNamesType;
import eu.europa.ec.markt.tsl.jaxb.tsl.MultiLangNormStringType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceHistoryInstanceType;

/**
 * Historical entry in the TL for the service
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (Mon, 06 Jun 2011) $
 */

class HistoricalTrustService extends AbstractTrustService {

    private ServiceHistoryInstanceType service;

    protected AbstractTrustService previousEntry;

    /**
     * The default constructor for TrustServiceHistoryEntry.
     */
    public HistoricalTrustService(ServiceHistoryInstanceType serviceHistoryInstance) {
        this.service = serviceHistoryInstance;
    }

    /**
     * Set the previous entry in the Trusted List
     *
     * @param previousEntry the previousEntry to set
     */
    void setPreviousEntry(AbstractTrustService previousEntry) {
        this.previousEntry = previousEntry;
    }

    @Override
    List<ExtensionType> getExtensions() {
        if (service != null && service.getServiceInformationExtensions() != null) {
            return service.getServiceInformationExtensions().getExtension();
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    DigitalIdentityListType getServiceDigitalIdentity() {

        return service.getServiceDigitalIdentity();
    }

    @Override
    String getStatus() {
        return service.getServiceStatus();
    }

    @Override
    Date getStatusStartDate() {
        return service.getStatusStartingTime().toGregorianCalendar().getTime();
    }

    @Override
    Date getStatusEndDate() {
        return previousEntry.getStatusStartDate();
    }

    @Override
    String getType() {
        return service.getServiceTypeIdentifier();
    }

    @Override
    String getServiceName() {

        /* Return the english name or the first name */
        InternationalNamesType names = service.getServiceName();
        for (MultiLangNormStringType s : names.getName()) {
            if ("en".equalsIgnoreCase(s.getLang())) {
                return s.getValue();
            }
        }
        return names.getName().get(0).getValue();
    }
}
