package eu.europa.esig.dss.validation;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractSignatureIdentifierBuilder implements SignatureIdentifierBuilder {
	
	protected final AdvancedSignature signature;
	
	/**
	 * The default constructor
	 * 
	 * @param signature {@link AdvancedSignature}
	 */
	public AbstractSignatureIdentifierBuilder(final AdvancedSignature signature) {
		this.signature = signature;
	}
	
	/**
	 * Builds {@code SignatureIdentifier} for the provided {@code AdvancedSignature}
	 * 
	 * @return {@link SignatureIdentifier}
	 */
	@Override
	public SignatureIdentifier build() {
		return new SignatureIdentifier(buildBinaries());
	}

	/**
	 * Builds unique binary data describing the signature object
	 * 
	 * @return a byte array
	 */
	protected byte[] buildBinaries() {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			writeParams(baos);
			return baos.toByteArray();
			
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}
	
	/**
	 * Write params of a signature to teh given {@code ByteArrayOutputStream}
	 * 
	 * @param baos {@link ByteArrayOutputStream} to enrich with the basic signature parameters
	 * @throws IOException if in exception has been thrown
	 */
	protected void writeParams(ByteArrayOutputStream baos) throws IOException {
		writeSigningTime(baos, signature.getSigningTime());
		writeSigningCertificateRefs(baos, signature.getCertificateSource().getSigningCertificateRefs());
		writeSignatureValue(baos, signature.getSignatureValue());
	}
	
	private void writeSigningTime(ByteArrayOutputStream baos, Date signingTime) throws IOException {
		try (DataOutputStream dos = new DataOutputStream(baos)) {
			if (signingTime != null) {
				dos.writeLong(signingTime.getTime());
			}
			dos.flush();
		}
	}
	
	private void writeSigningCertificateRefs(ByteArrayOutputStream baos, List<CertificateRef> signingCertificateRefs) throws IOException {
		if (Utils.isCollectionNotEmpty(signingCertificateRefs)) {
			for (CertificateRef certificateRef : signingCertificateRefs) {
				writeString(baos, certificateRef.getDSSIdAsString());
			}
		}
	}
	
	private void writeSignatureValue(ByteArrayOutputStream baos, byte[] signatureValue) throws IOException {
		try (DataOutputStream dos = new DataOutputStream(baos)) {
			if (Utils.isArrayNotEmpty(signatureValue)) {
				dos.write(signatureValue);
			}
			dos.flush();
		}
	}
	
	/**
	 * The method used to write a {@code str} into {@code baos}
	 * 
	 * @param baos {@link ByteArrayOutputStream} to write String into
	 * @param str {@link String}
	 * @throws IOException if in exception occurs
	 */
	protected void writeString(ByteArrayOutputStream baos, String str) throws IOException {
		try (DataOutputStream dos = new DataOutputStream(baos)) {
			if (str != null) {
				dos.writeChars(str);
			}
			dos.flush();
		}
	}

}
