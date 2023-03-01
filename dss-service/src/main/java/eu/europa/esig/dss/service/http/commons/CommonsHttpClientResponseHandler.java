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
package eu.europa.esig.dss.service.http.commons;

import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.StatusLine;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

/**
 * This is a default implementation of {@code HttpClientResponseHandler<byte[]>} to be used within
 * {@code eu.europa.esig.dss.service.http.commons.CommonsDataLoader}.
 * This class is used to read the {@code org.apache.hc.core5.http.ClassicHttpResponse} and
 * return a byte[] representing the obtained data in case of success.
 */
public class CommonsHttpClientResponseHandler implements HttpClientResponseHandler<byte[]> {

    /** The list of accepted statuses for a successful connection */
    private static final List<Integer> ACCEPTED_HTTP_STATUS = Collections.singletonList(HttpStatus.SC_OK);

    /** Defines the accepted HTTP statuses */
    private List<Integer> acceptedHttpStatuses = ACCEPTED_HTTP_STATUS;

    /**
     * Default constructor to instantiate the {@code CommonsHttpClientResponseHandler}
     */
    public CommonsHttpClientResponseHandler() {
        // empty
    }

    /**
     * Returns a list of accepted HTTP status numbers
     *
     * @return a list of accepted HTTP status numbers
     */
    public List<Integer> getAcceptedHttpStatuses() {
        return acceptedHttpStatuses;
    }

    /**
     * This allows to set a list of accepted http status.
     * Example: 200 (OK)
     *
     * @param acceptedHttpStatuses
     *            a list of integer which correspond to the http status code
     */
    public void setAcceptedHttpStatuses(List<Integer> acceptedHttpStatuses) {
        this.acceptedHttpStatuses = acceptedHttpStatuses;
    }

    @Override
    public byte[] handleResponse(ClassicHttpResponse classicHttpResponse) throws IOException {
        try {
            final StatusLine statusLine = new StatusLine(classicHttpResponse);
            final int statusCode = statusLine.getStatusCode();
            final String reasonPhrase = statusLine.getReasonPhrase();

            if (!acceptedHttpStatuses.contains(statusCode)) {
                String reason = Utils.isStringNotEmpty(reasonPhrase) ? " / reason : " + reasonPhrase : "";
                throw new IOException("Not acceptable HTTP Status (HTTP status code : " + statusCode + reason + ")");
            }

            final HttpEntity responseEntity = classicHttpResponse.getEntity();
            if (responseEntity == null) {
                throw new IOException("No message entity for this response");
            }

            return getContent(responseEntity);

        } finally {
            closeQuietly(classicHttpResponse);
        }
    }

    /**
     * Gets content of the response
     *
     * @param responseEntity {@link HttpEntity}
     * @return byte array
     * @throws IOException if an exception occurs
     */
    protected byte[] getContent(final HttpEntity responseEntity) throws IOException {
        try (InputStream content = responseEntity.getContent()) {
            return DSSUtils.toByteArray(content);
        }
    }

    /**
     * This method closes the {@code ClassicHttpResponse}
     *
     * @param classicHttpResponse {@link ClassicHttpResponse} to close
     */
    protected void closeQuietly(ClassicHttpResponse classicHttpResponse) {
        if (classicHttpResponse != null) {
            EntityUtils.consumeQuietly(classicHttpResponse.getEntity());
            Utils.closeQuietly(classicHttpResponse);
        }
    }

}
