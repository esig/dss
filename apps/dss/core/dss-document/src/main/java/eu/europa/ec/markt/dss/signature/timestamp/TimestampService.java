/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2014 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2014 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.signature.timestamp;

import eu.europa.ec.markt.dss.parameter.ContentTimestampReference;
import eu.europa.ec.markt.dss.parameter.TimestampParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * This class acts as a middleware providing
 */
public class TimestampService {

	private TSPSource tspSource;
	private CertificatePool certificatePool;

	//Define method calling ContentTimestampGenerator
	//@return a DSSDocument containing the contentTimestamp

	public TimestampService(TSPSource tspSource, CertificatePool certificatePool) {
		this.tspSource = tspSource;
		this.certificatePool = certificatePool;
	}

	/**
	 * Method that generates a ContentTimestamp as a DSSDocument
	 *
	 * @param parameters
	 * @return contentTimestamp as an InMemoryDocument
	 */
	public DSSDocument generateContentTimestamp(final TimestampParameters parameters) {

		ContentTimestampGenerator generator = new ContentTimestampGenerator(tspSource, certificatePool);
		TimestampToken token = generator.generateContentTimestamp(parameters);

		InMemoryDocument document = new InMemoryDocument(token.getEncoded());

		return document;
	}

	/**
	 * Method that generates a ContentTimestamp as a DSS TimestampToken
	 * @param parameters the timestamp parameters to consider
	 * @return the ContentTimestamp as a DSS TimestampToken
	 */
	public TimestampToken generateContentTimestampAsTimestampToken( final TimestampParameters parameters) {

		ContentTimestampGenerator generator = new ContentTimestampGenerator(tspSource, certificatePool);
		TimestampToken token = generator.generateContentTimestamp(parameters);
		return token;
	}

	/**
	 * Method that generates an AllDataObjectsTimestamp as a DSSDocument
	 *
	 * @param parameters the timestamp parameters to consider
	 * @return an InMemoryDocument containing the encoded timestamp
	 */
	public DSSDocument generateAllDataObjectsTimestamp(final TimestampParameters parameters) {

		final ContentTimestampGenerator generator = new ContentTimestampGenerator(tspSource, certificatePool);
		final TimestampToken token = generator.generateAllDataObjectsTimestamp(parameters);

		final InMemoryDocument inMemoryDocument = new InMemoryDocument(token.getEncoded());

		return inMemoryDocument;
	}

	/**
	 * Method that generates an AllDataObjectsTimestamp as a DSS TimestampToken
	 *
	 * @param parameters the timestamp parameters to consider
	 * @return the AllDataObjectsTimestamp as a DSS TimestampToken
	 */
	public TimestampToken generateAllDataObjectsTimestampAsTimestampToken(final TimestampParameters parameters) {
		final ContentTimestampGenerator generator = new ContentTimestampGenerator(tspSource, certificatePool);
		final TimestampToken token = generator.generateAllDataObjectsTimestamp(parameters);
		return token;
	}

	/**
	 * Method that generates an IndividualDataObjectsTimestamp as a DSSDocument
	 *
	 * @param parameters the timestamp parameters to consider
	 * @return an InMemoryDocument containing the encoded timestamp
	 */
	public DSSDocument generateIndividualDataObjectsTimestamp(final TimestampParameters parameters) {

		final ContentTimestampGenerator generator = new ContentTimestampGenerator(tspSource, certificatePool);
		final TimestampToken token = generator.generateIndividualDataObjectsTimestamp(parameters);

		final InMemoryDocument inMemoryDocument = new InMemoryDocument(token.getEncoded());

		return inMemoryDocument;
	}

	/**
	 * Method that generates an IndividualDataObjectsTimestamp as a DSS TimestampToken
	 *
	 * @param parameters the timestamp parameters to consider
	 * @return the IndividualDataObjectsTimestamp as a DSS TimestampToken
	 */
	public TimestampToken generateIndividualDataObjectsTimestampAsTimestampToken(final TimestampParameters parameters) {
		final ContentTimestampGenerator generator = new ContentTimestampGenerator(tspSource, certificatePool);
		final TimestampToken token = generator.generateIndividualDataObjectsTimestamp(parameters);
		return token;
	}
}
