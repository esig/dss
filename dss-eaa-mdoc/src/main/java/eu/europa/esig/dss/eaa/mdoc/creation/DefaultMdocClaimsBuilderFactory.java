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
package eu.europa.esig.dss.eaa.mdoc.creation;

import eu.europa.esig.dss.eaa.mdoc.MdocConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default MdocClaimsBuilderFactory loading one of the supported implementations.
 *
 */
public class DefaultMdocClaimsBuilderFactory implements MdocClaimsBuilderFactory {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultMdocClaimsBuilderFactory.class);

    /**
     * Default constructor
     */
    public DefaultMdocClaimsBuilderFactory() {
        // empty
    }

    @Override
    public MdocClaimsBuilder create(MdocPayloadParameters payloadParameters) {
        String docType = payloadParameters.getDocType();
        if (MdocConstants.ISO18013_5_MDL_DOC_TYPE.equals(docType)) {
            return DefaultMdocClaimsBuilder.ISO180135MDLClaimsBuilder.getInstance();
        } else if (MdocConstants.ISO23220_1_MID_DOC_TYPE.equals(docType)) {
            return DefaultMdocClaimsBuilder.ISO232201MIDClaimsBuilder.getInstance();
        } else if (MdocConstants.EUDI_PID_DOC_TYPE.equals(docType)) {
            return DefaultMdocClaimsBuilder.EUDIPIDMdocClaimsBuilder.getInstance();
        }
        LOG.warn("The docType '{}' is not supported by the implementation! Default implementation of MdocClaimsBuilderFactory is selected." +
                "Should you need a specific configuration, please configure a custom MdocClaimsBuilderFactory.", docType);
        return DefaultMdocClaimsBuilder.ISO232201MIDClaimsBuilder.getInstance(); // default
    }

}
