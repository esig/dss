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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.signature.AbstractGetDataToSignHelper;
import eu.europa.esig.dss.asic.xades.signature.GetDataToSignASiCWithXAdESHelper;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * An abstract class to generate a DataToSign with ASiC-E with XAdES
 */
public class DataToSignASiCEWithXAdESHelper extends AbstractGetDataToSignHelper implements GetDataToSignASiCWithXAdESHelper {

    /**
     * The default constructor
     *
     * @param asicContent {@link ASiCContent}
     */
    public DataToSignASiCEWithXAdESHelper(final ASiCContent asicContent) {
        super(asicContent);
    }

    @Override
    public List<DSSDocument> getToBeSigned() {
        return asicContent.getSignedDocuments();
    }

    @Override
    public boolean isOpenDocument() {
        return false;
    }

}
