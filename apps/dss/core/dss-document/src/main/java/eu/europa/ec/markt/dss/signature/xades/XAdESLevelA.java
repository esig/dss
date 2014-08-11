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

package eu.europa.ec.markt.dss.signature.xades;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;

/**
 * Holds level A aspects of XAdES
 *
 * @version $Revision$ - $Date$
 */

public class XAdESLevelA extends XAdESLevelXL {

    private static final Logger LOG = LoggerFactory.getLogger(XAdESLevelA.class);

    /**
     * The default constructor for XAdESLevelA.
     */
    public XAdESLevelA(CertificateVerifier certificateVerifier) {

        super(certificateVerifier);
    }

    /**
     * Adds the ArchiveTimeStamp element which is an unsigned property qualifying the signature. The hash sent to the TSA
     * (messageImprint) is computed on the XAdES-X-L form of the electronic signature and the signed data objects.<br>
     * <p/>
     * A XAdES-A form MAY contain several ArchiveTimeStamp elements.
     *
     * @see XAdESLevelXL#extendSignatureTag()
     */
    @Override
    protected void extendSignatureTag() throws DSSException {

        /* Up to -XL */
        super.extendSignatureTag();

        xadesSignature.checkSignatureIntegrity();

        final byte[] data = xadesSignature.getArchiveTimestampData(null);
        final DigestAlgorithm timestampDigestAlgorithm = params.getSignatureTimestampParameters().getDigestAlgorithm();
        final byte[] digestBytes = DSSUtils.digest(timestampDigestAlgorithm, data);
        createXAdESTimeStampType(TimestampType.ARCHIVE_TIMESTAMP, XAdESSignature.DEFAULT_TIMESTAMP_CREATION_CANONICALIZATION_METHOD, digestBytes);
    }
}
