package eu.europa.esig.dss.spi.x509.tsp;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.IdentifierBuilder;
import eu.europa.esig.dss.utils.Utils;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Objects;

/**
 * Builds an {@code eu.europa.esig.dss.spi.x509.tsp.TimestampTokenIdentifier}
 * for the provided {@code eu.europa.esig.dss.spi.x509.tsp.TimestampToken}.
 * This class provided a format independent implementation.
 * Please use inherited classed for format-specific implementations.
 *
 */
public class TimestampIdentifierBuilder implements IdentifierBuilder {

    private static final long serialVersionUID = 8108224076397826022L;

    /** Time-stamp token to build an identifier for */
    protected final byte[] timestampTokenBinaries;

    /** Name of the document containing the time-stamp token */
    private String filename;

    /**
     * Default constructor to build an implementation independent identifier
     *
     * @param timestampTokenBinaries byte array representing a DER-encoded time-stamp binary octets
     */
    public TimestampIdentifierBuilder(final byte[] timestampTokenBinaries) {
        Objects.requireNonNull(timestampTokenBinaries, "Timestamp token binaries cannot be null!");
        this.timestampTokenBinaries = timestampTokenBinaries;
    }

    /**
     * Sets a time-stamp document filename
     *
     * @param filename {@link String}
     * @return this {@link TimestampIdentifierBuilder}
     */
    public TimestampIdentifierBuilder setFilename(String filename) {
        this.filename = filename;
        return this;
    }

    /**
     * Builds {@code TimestampTokenIdentifier} for the provided {@code eu.europa.esig.dss.spi.x509.tsp.TimestampToken}
     *
     * @return {@link TimestampTokenIdentifier}
     */
    @Override
    public TimestampTokenIdentifier build() {
        return new TimestampTokenIdentifier(buildBinaries());
    }

    /**
     * Builds unique binary data describing the time-stamp token
     *
     * @return a byte array
     */
    protected byte[] buildBinaries() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            writeTimestampBinaries(baos);
            writeTimestampPosition(baos);
            return baos.toByteArray();

        } catch (IOException e) {
            throw new DSSException(String.format("An error occurred while building an Identifier : %s", e.getMessage()), e);
        }
    }

    /**
     * Writes DER-encoded binaries of the current time-stamp token to the given {@code ByteArrayOutputStream}
     *
     * @param baos {@link ByteArrayOutputStream} to write time-stamp binaries to
     * @throws IOException if an exception occurs
     */
    protected void writeTimestampBinaries(ByteArrayOutputStream baos) throws IOException {
        baos.write(timestampTokenBinaries);
    }

    /**
     * Writes the current time-stamp position within a document
     *
     * @param baos {@link ByteArrayOutputStream} to add data to
     * @throws IOException if an exception occurs
     */
    protected void writeTimestampPosition(ByteArrayOutputStream baos) throws IOException {
        try (DataOutputStream dos = new DataOutputStream(baos)) {
            String positionId = getUniquePositionId();
            if (positionId != null) {
                dos.writeChars(positionId);
            }
            dos.flush();
        }
    }

    /**
     * Returns Id representing a current signature position in a file,
     * considering its pre-siblings, master signatures when present
     *
     * @return {@link String} position id
     */
    protected String getUniquePositionId() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(getTimestampPosition());
        if (filename != null) {
            stringBuilder.append(filename);
        }
        return stringBuilder.toString();
    }

    /**
     * Returns a position of a time-stamp token within a document among other time-stamps
     *
     * @return time-stamp position identifier
     */
    protected Object getTimestampPosition() {
        // return empty string by default
        return Utils.EMPTY_STRING;
    }

}
