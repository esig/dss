package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.utils.Utils;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;

/**
 * The abstract SignatureIdentifier builder
 */
public abstract class AbstractSignatureIdentifierBuilder implements SignatureIdentifierBuilder {

	/** The signature to build identifier for */
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
			writeSignedProperties(baos);
			writeSignaturePosition(baos);
			return baos.toByteArray();
			
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}
	
	/**
	 * Write signed properties of a signature to the given {@code ByteArrayOutputStream}
	 * 
	 * @param baos {@link ByteArrayOutputStream} to enrich with the basic signature parameters
	 * @throws IOException if in exception has been thrown
	 */
	protected void writeSignedProperties(ByteArrayOutputStream baos) throws IOException {
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

	/**
	 * Writes the current signature position between other signature entries on the same level
	 *
	 * @param baos {@link ByteArrayOutputStream} to add data to
	 * @throws IOException if an exception occurs
	 */
	protected void writeSignaturePosition(ByteArrayOutputStream baos) throws IOException {
		writeString(baos, getPositionId());
	}

	/**
	 * Returns Id repesenting a current signature position in a file,
	 * considering its pre-siblings, master signatures when present
	 * 
	 * @return {@link String} position id
	 */
	protected String getPositionId() {
		StringBuilder stringBuilder = new StringBuilder();
		
		AdvancedSignature masterSignature = signature.getMasterSignature();
		if (masterSignature != null) {
			stringBuilder.append(masterSignature.getId());
			stringBuilder.append(getCounterSignaturePosition(masterSignature));
		} else {
			stringBuilder.append(getSignatureFilePosition());
		}
		
		return stringBuilder.toString();
	}
	
	/**
	 * Returns a current counter signature position in its master signature
	 * 
	 * @param masterSignature {@link AdvancedSignature} to analyze
	 * @return counter signature position
	 */
	protected abstract Object getCounterSignaturePosition(AdvancedSignature masterSignature);
	
	/**
	 * Returns a position of a signature in the provided file
	 * 
	 * @return signature position in a file
	 */
	protected abstract Object getSignatureFilePosition();

}
