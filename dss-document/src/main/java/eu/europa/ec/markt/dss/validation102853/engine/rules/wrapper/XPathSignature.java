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
package eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper;

import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * This is the utility class that allows to extract information from the XmlDom objects using xPath queries.
 *
 *
 */
public class XPathSignature {

    /**
     * This method returns the signing certificate.
     *
     * @param signature
     * @return
     */
    public static int getSigningCertificateId(final XmlDom signature) {

        final int signingCertId = signature.getIntValue("./SigningCertificate/@Id");
        return signingCertId;
    }

    /**
     * This method returns the certificate id. This id is extracted either from the ChainCertificate, or Certificate.
     *
     * @param xmlDomObject
     * @return
     */
    public static int getCertificateId(final XmlDom xmlDomObject) {

        final int certificateId = xmlDomObject.getIntValue("./@Id");
        return certificateId;
    }

}
