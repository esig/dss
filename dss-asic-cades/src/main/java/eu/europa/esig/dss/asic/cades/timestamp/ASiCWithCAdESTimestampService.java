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
package eu.europa.esig.dss.asic.cades.timestamp;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.DefaultASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESASiCContentBuilder;
import eu.europa.esig.dss.asic.cades.signature.GetDataToSignASiCWithCAdESHelper;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * This class is used to create a timestamp covering signer files
 *
 */
public class ASiCWithCAdESTimestampService {

    /**
     * TSPSource used to retrieve a timestamp response
     */
    private final TSPSource tspSource;

    /**
     * Defines rules for filename creation for timestamp file.
     */
    private final ASiCWithCAdESFilenameFactory asicFilenameFactory;

    /**
     * Default constructor
     *
     * @param tspSource {@link TSPSource}
     */
    public ASiCWithCAdESTimestampService(final TSPSource tspSource) {
        this(tspSource, new DefaultASiCWithCAdESFilenameFactory());
    }

    /**
     * Constructor with filename factory
     *
     * @param tspSource {@link TSPSource}
     * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
     */
    public ASiCWithCAdESTimestampService(final TSPSource tspSource, final ASiCWithCAdESFilenameFactory asicFilenameFactory) {
        this.tspSource = tspSource;
        this.asicFilenameFactory = asicFilenameFactory;
    }

    /**
     * The method is used to timestamp a list of {@code documents}
     *
     * @param documents a list of {@link DSSDocument}s
     * @param parameters {@link ASiCWithCAdESTimestampParameters}
     * @return {@link DSSDocument} timestamped archive
     */
    public DSSDocument timestamp(List<DSSDocument> documents, ASiCWithCAdESTimestampParameters parameters) {
        ASiCContent asicContent = new ASiCWithCAdESASiCContentBuilder()
                .build(documents, parameters.aSiC().getContainerType());
        asicContent = timestamp(asicContent, parameters);
        return ZipUtils.getInstance().createZipArchive(asicContent, parameters.getZipCreationDate());
    }

    /**
     * This method is used to add a timestamp to the given {@code ASiCContent}
     * 
     * @param asicContent {@link ASiCContent} to timestamp signed documents from
     * @param parameters {@link ASiCWithCAdESTimestampParameters}
     * @return {@link ASiCContent} containing the timestamp and the related XML Manifest for ASiC-E container
     */
    public ASiCContent timestamp(ASiCContent asicContent, ASiCWithCAdESTimestampParameters parameters) {
        GetDataToSignASiCWithCAdESHelper dataToSignHelper = new ASiCWithCAdESTimestampDataToSignHelperBuilder(asicFilenameFactory)
                .build(asicContent, parameters);

        DSSDocument toBeTimestamped = dataToSignHelper.getToBeSigned();
        if (ASiCContainerType.ASiC_E == parameters.aSiC().getContainerType()) {
            asicContent.getManifestDocuments().add(toBeTimestamped); // XML Document in case of ASiC-E container
        }

        DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
        TimestampBinary timestampBinary = tspSource.getTimeStampResponse(
                digestAlgorithm, Utils.fromBase64(toBeTimestamped.getDigest(digestAlgorithm)));

        DSSDocument timestampToken = new InMemoryDocument(
                DSSASN1Utils.getDEREncoded(timestampBinary), asicFilenameFactory.getTimestampFilename(asicContent), MimeType.TST);
        ASiCUtils.addOrReplaceDocument(asicContent.getTimestampDocuments(), timestampToken);

        return asicContent;
    }

}
