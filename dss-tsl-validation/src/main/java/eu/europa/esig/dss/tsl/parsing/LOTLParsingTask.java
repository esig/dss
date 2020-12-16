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
package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.tsl.function.LOTLSigningCertificatesAnnouncementSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.PivotSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.converter.OtherTSLPointerConverter;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Parses a LOTL and returns {@code LOTLParsingResult}
 */
public class LOTLParsingTask extends AbstractParsingTask implements Supplier<LOTLParsingResult> {

	private static final Logger LOG = LoggerFactory.getLogger(LOTLParsingTask.class);

	/** The LOTLSource to parse */
	private final LOTLSource lotlSource;

	/**
	 * The default constructor
	 *
	 * @param document {@link DSSDocument} LOTL document to parse
	 * @param lotlSource {@link LOTLSource}
	 */
	public LOTLParsingTask(DSSDocument document, LOTLSource lotlSource) {
		super(document);
		Objects.requireNonNull(lotlSource, "The LOTLSource is null");
		this.lotlSource = lotlSource;
	}

	@Override
	public LOTLParsingResult get() {

		LOTLParsingResult result = new LOTLParsingResult();

		TrustStatusListType jaxbObject = getJAXBObject();

		parseSchemeInformation(result, jaxbObject.getSchemeInformation());

		return result;
	}

	private void parseSchemeInformation(LOTLParsingResult result, TSLSchemeInformationType schemeInformation) {

		commonParseSchemeInformation(result, schemeInformation);

		extractOtherTSLPointers(result, schemeInformation);

		extractSchemeInformationURI(result, schemeInformation);

	}

	private void extractOtherTSLPointers(LOTLParsingResult result, TSLSchemeInformationType schemeInformation) {
		OtherTSLPointersType otherTSLPointersType = schemeInformation.getPointersToOtherTSL();
		if (otherTSLPointersType != null && Utils.isCollectionNotEmpty(otherTSLPointersType.getOtherTSLPointer())) {

			List<OtherTSLPointerType> otherTSLPointers = otherTSLPointersType.getOtherTSLPointer();

			OtherTSLPointerConverter converter = new OtherTSLPointerConverter();

			result.setLotlPointers(otherTSLPointers.stream().filter(lotlSource.getLotlPredicate()).map(converter).collect(Collectors.toList()));

			result.setTlPointers(otherTSLPointers.stream().filter(lotlSource.getTlPredicate()).map(converter).collect(Collectors.toList()));
		}
	}

	private void extractSchemeInformationURI(LOTLParsingResult result, TSLSchemeInformationType schemeInformation) {
		NonEmptyMultiLangURIListType schemeInformationURI = schemeInformation.getSchemeInformationURI();
		if (schemeInformationURI != null) {
			extractSigningCertificatesAnnouncementURL(result, schemeInformationURI);
			extractPivotURLs(result, schemeInformationURI);
		}
	}

	private void extractSigningCertificatesAnnouncementURL(LOTLParsingResult result, NonEmptyMultiLangURIListType schemeInformationURI) {
		LOTLSigningCertificatesAnnouncementSchemeInformationURI signingCertificatesAnnouncementPredicate = lotlSource.getSigningCertificatesAnnouncementPredicate();
		if (signingCertificatesAnnouncementPredicate != null) {
			List<String> uris = schemeInformationURI.getURI().stream().filter(signingCertificatesAnnouncementPredicate).map(t -> t.getValue())
					.collect(Collectors.toList());
			if (Utils.isCollectionNotEmpty(uris)) {
				if (uris.size() > 1) {
					LOG.warn("More than 1 LOTLSigningCertificatesAnnouncement URI found (returns the first entry) : {}", uris);
				}
				result.setSigningCertificateAnnouncementURL(uris.get(0));
			}
		}
	}

	private void extractPivotURLs(LOTLParsingResult result, NonEmptyMultiLangURIListType schemeInformationURI) {
		if (lotlSource.isPivotSupport()) {
			List<String> uris = schemeInformationURI.getURI().stream().filter(new PivotSchemeInformationURI()).map(t -> t.getValue())
					.collect(Collectors.toList());
			result.setPivotURLs(uris);
		}
	}

}
