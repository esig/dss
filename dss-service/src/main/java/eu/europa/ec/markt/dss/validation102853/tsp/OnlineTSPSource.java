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
package eu.europa.ec.markt.dss.validation102853.tsp;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLConnection;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.NonceSource;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;

/**
 * Class encompassing a RFC 3161 TSA, accessed through HTTP(S) to a given URI
 *
 */
public class OnlineTSPSource implements TSPSource {

	private static final Logger logger = LoggerFactory.getLogger(OnlineTSPSource.class);

	/**
	 * The URL of the TSP server
	 */
	private String tspServer;

	/**
	 * The requested policy oid
	 */
	private ASN1ObjectIdentifier policyOid;

	/**
	 * The data loader used to retrieve the TSP response.
	 */
	private DataLoader dataLoader;

	/**
	 * This variable is used to prevent the replay attack.
	 */
	private NonceSource nonceSource;

	/**
	 * The default constructor for OnlineTSPSource.
	 */
	public OnlineTSPSource() {
		this(null);
	}

	/**
	 * Build a OnlineTSPSource that will query the specified URL
	 *
	 * @param tspServer
	 */
	public OnlineTSPSource(final String tspServer) {
		this.tspServer = tspServer;
	}

	/**
	 * Set the URL of the TSA
	 *
	 * @param tspServer
	 */
	public void setTspServer(final String tspServer) {
		this.tspServer = tspServer;
	}

	/**
	 * Set the request policy
	 *
	 * @param policyOid
	 */
	@Override
	public void setPolicyOid(final String policyOid) {
		this.policyOid = new ASN1ObjectIdentifier(policyOid);
	}

	@Override
	public String getUniqueId(final byte[] digestValue) {
		byte[] digest;
		if (nonceSource !=null){
			digest = DSSUtils.digest(DigestAlgorithm.MD5, digestValue, nonceSource.getNonce().toByteArray());
		} else {
			digest = DSSUtils.digest(DigestAlgorithm.MD5, digestValue);
		}
		return Hex.encodeHexString(digest);
	}

	/**
	 * Set the DataLoader to use for querying the TSP server.
	 *
	 * @param dataLoader the component that allows to retrieve the TSP response using HTTP.
	 */
	public void setDataLoader(final DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	/**
	 * Set the NonceSource to use for querying the TSP server.
	 *
	 * @param nonceSource the component that prevents the replay attack.
	 */
	public void setNonceSource(NonceSource nonceSource) {
		this.nonceSource = nonceSource;
	}

	@Override
	public TimeStampToken getTimeStampResponse(final DigestAlgorithm digestAlgorithm, final byte[] digest) throws DSSException {
		try {
			if (logger.isTraceEnabled()) {
				logger.trace("Timestamp digest algorithm: " + digestAlgorithm.getName());
				logger.trace("Timestamp digest value    : " + Hex.encodeHexString(digest));
			}

			// Setup the time stamp request
			final TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
			tsqGenerator.setCertReq(true);
			if (policyOid != null) {
				tsqGenerator.setReqPolicy(policyOid);
			}

			ASN1ObjectIdentifier asn1ObjectIdentifier = digestAlgorithm.getOid();
			TimeStampRequest timeStampRequest = null;
			if (nonceSource == null) {
				timeStampRequest = tsqGenerator.generate(asn1ObjectIdentifier, digest);
			} else {
				timeStampRequest = tsqGenerator.generate(asn1ObjectIdentifier, digest, nonceSource.getNonce());
			}

			final byte[] requestBytes = timeStampRequest.getEncoded();

			// Call the communications layer
			byte[] respBytes;
			if (dataLoader != null) {
				respBytes = dataLoader.post(tspServer, requestBytes);
			} else {
				respBytes = getTSAResponse(requestBytes);
			}

			// Handle the TSA response
			final TimeStampResponse timeStampResponse = new TimeStampResponse(respBytes);

			// Validates nonce, policy id, ... if present
			timeStampResponse.validate(timeStampRequest);

			String statusString = timeStampResponse.getStatusString();
			if (statusString !=null){
				logger.info("Status: " + statusString);
			}

			final TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();

			if (timeStampToken != null) {
				logger.info("TSP SID : SN " + timeStampToken.getSID().getSerialNumber() + ", Issuer " + timeStampToken.getSID().getIssuer());
			}

			return timeStampToken;
		} catch (TSPException e) {
			throw new DSSException("Invalid TSP response", e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Get timestamp token - communications layer
	 *
	 * @return - byte[] - TSA response, raw bytes (RFC 3161 encoded)
	 */
	protected byte[] getTSAResponse(final byte[] requestBytes) throws DSSException {

		// Setup the TSA connection
		final URLConnection tsaConnection = DSSUtils.openURLConnection(tspServer);

		tsaConnection.setDoInput(true);
		tsaConnection.setDoOutput(true);
		tsaConnection.setUseCaches(false);
		tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
		tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");

		DSSUtils.writeToURLConnection(tsaConnection, requestBytes);

		// Get TSA response as a byte array
		byte[] respBytes = getReadFromURLConnection(tsaConnection);
		final String encoding = tsaConnection.getContentEncoding();
		if ("base64".equalsIgnoreCase(encoding)) {
			respBytes = Base64.decodeBase64(respBytes);
		}
		return respBytes;
	}

	private byte[] getReadFromURLConnection(final URLConnection tsaConnection) throws DSSException {
		try {
			final InputStream inputStream = tsaConnection.getInputStream();
			return IOUtils.toByteArray(inputStream);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}
}
