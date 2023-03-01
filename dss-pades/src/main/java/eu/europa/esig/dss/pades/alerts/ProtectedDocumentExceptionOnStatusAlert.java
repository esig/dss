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
package eu.europa.esig.dss.pades.alerts;

import eu.europa.esig.dss.alert.AbstractStatusAlert;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.status.Status;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;

/**
 * This alert is used to throw a {@code eu.europa.esig.dss.pades.exception.ProtectedDocumentException}
 * when the corresponding check fails
 *
 */
public class ProtectedDocumentExceptionOnStatusAlert extends AbstractStatusAlert {

    /**
     * The default constructor
     */
    public ProtectedDocumentExceptionOnStatusAlert() {
        super(new AlertHandler<Status>() {

            @Override
            public void process(Status object) {
                throw new ProtectedDocumentException(object.getErrorString());
            }

        });
    }

}
