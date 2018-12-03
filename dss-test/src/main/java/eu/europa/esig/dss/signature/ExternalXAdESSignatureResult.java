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
package eu.europa.esig.dss.signature;

import java.util.Date;

/**
 * Class used during test to represent the result returned by
 * an external XAdES signature process.
 */
public class ExternalXAdESSignatureResult extends ExternalSignatureResult {
    private Date signingDate;
    private byte[] signedAdESObject;

    public Date getSigningDate() { return signingDate; }

    public void setSigningDate(Date signingDate) { this.signingDate = signingDate; }

    public byte[] getSignedAdESObject() {
        return signedAdESObject;
    }

    public void setSignedAdESObject(byte[] signedAdESObject) {
        this.signedAdESObject = signedAdESObject;
    }
}
